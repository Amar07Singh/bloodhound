#!/usr/bin/env python3
"""
BLOODHOUND — agent_stream.py
The loop as a GENERATOR: instead of returning only a final conclusion, it YIELDS
one typed event per step. The FastAPI SSE endpoint forwards these to the browser,
and the React UI renders each as it arrives. This is what makes the reasoning
"stream" and kills dead air.

Event types the UI understands:
  status       {msg}                         - "thinking", "executing", etc.
  think        {interpretation, hypothesis}  - left column reasoning text
  query        {template_id, params, eql?}   - the query about to run
  raw          {json}                         - raw result, shown ~2s (credibility)
  finding      {summary, count}              - interpreted result
  graph_edge   {from, to, label}            - center: draw a lateral-movement edge
  timeline     {when, desc, kind, flag}     - right: pin a timeline entry
  conclude     {conclusion}                  - final verdict
  done         {queries}                     - stream finished

Reuses the SAME nodes/seatbelt as agent.py — this is a streaming wrapper, not a
second brain.
"""
from __future__ import annotations
import json, time
from agent import decide_with_retry, build_menu, MAX_ITERS
from agent_brains import summarize


def _graph_edge_from(result):
    """If a query revealed a host pivot, yield the edge to draw."""
    if result.get("kind") == "analyze":
        for pair in result.get("sequences", []):
            a, b = pair[0].get("host.name"), pair[1].get("host.name")
            if a and b and a != b:
                return {"from": a, "to": b, "label": pair[0].get("user.name", "")}
    return None


def _timeline_from(result):
    """Turn the most interesting event in a result into a timeline pin."""
    rows = (result.get("events") or
            [e for pair in result.get("sequences", []) for e in pair])
    pins = []
    for e in rows:
        b = e.get("network.bytes", 0)
        if b and b > 1_000_000_000 and not str(e.get("destination.ip", "")).startswith("10."):
            pins.append({"when": e.get("@timestamp", "")[11:19],
                         "desc": f"{round(b/1e9,2)}GB to {e.get('destination.ip')}",
                         "kind": "exfil", "flag": "EXFILTRATION", "confidence": "high"})
        elif e.get("event.action") == "logon":
            pins.append({"when": e.get("@timestamp", "")[11:19],
                         "desc": f"{e.get('user.name')} @ {e.get('host.name')} "
                                 f"({e.get('source.geo.city_name','?')})",
                         "kind": "logon", "flag": "", "confidence": "medium"})
    return pins[:3]


def hunt_stream(llm, executor, alert, *, pause=0.0):
    """Yield events as the hunt progresses. `pause` lets the demo breathe
    (e.g. 2s on raw JSON); set 0 for tests."""
    menu = build_menu()
    history, transcript = [], []
    yield {"type": "status", "msg": "BLOODHOUND activated — beginning retrospective hunt"}

    while True:
        yield {"type": "status", "msg": "reasoning about evidence…"}
        d = decide_with_retry(llm, alert, history, menu)
        yield {"type": "think", "interpretation": d["interpretation"],
               "hypothesis": d.get("next_hypothesis", "")}

        if d.get("conclude") or len(history) >= MAX_ITERS:
            yield {"type": "conclude",
                   "conclusion": d.get("conclusion") or d["interpretation"]}
            break

        tid, params = d["template_id"], d.get("params", {})
        yield {"type": "query", "template_id": tid, "params": params}
        yield {"type": "status", "msg": f"executing {tid} against Elasticsearch…"}

        result = executor.run(tid, params)

        # raw JSON first (credibility beat) — UI holds it ~2s
        sample = (result.get("events") or
                  [e for p in result.get("sequences", []) for e in p])[:2]
        yield {"type": "raw", "json": json.dumps(sample, indent=2)[:1200]}
        if pause:
            time.sleep(pause)

        summary = summarize(result)
        history.append({"template_id": tid, "params": params,
                        "result": result, "summary": summary})
        yield {"type": "finding", "summary": summary, "count": result["count"]}

        edge = _graph_edge_from(result)
        if edge:
            yield {"type": "graph_edge", **edge}
        for pin in _timeline_from(result):
            yield {"type": "timeline", **pin}

    yield {"type": "done", "queries": len(history)}


if __name__ == "__main__":
    # offline proof: print every event the UI would receive
    from agent import ALERT
    from agent_brains import MockLLM, OfflineExecutor
    n = 0
    for ev in hunt_stream(MockLLM(), OfflineExecutor("logs.ndjson"), ALERT):
        n += 1
        t = ev["type"]
        if t == "think":
            print(f"[{t}] {ev['interpretation'][:80]}")
        elif t == "query":
            print(f"[{t}] {ev['template_id']} {ev['params']}")
        elif t == "raw":
            print(f"[{t}] {ev['json'][:60].replace(chr(10),' ')}...")
        elif t == "finding":
            print(f"[{t}] {ev['summary'][:80]}")
        elif t == "graph_edge":
            print(f"[{t}] {ev['from']} -> {ev['to']}")
        elif t == "timeline":
            print(f"[{t}] {ev['when']} {ev['desc'][:50]} [{ev['flag']}]")
        elif t == "conclude":
            print(f"[{t}] {ev['conclusion'][:80]}")
        else:
            print(f"[{t}] {ev.get('msg','')}")
    print(f"\n{n} events emitted — this is exactly what the browser receives.")

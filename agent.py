#!/usr/bin/env python3
"""
BLOODHOUND — agent.py  (the reasoning loop: Days 4-5)
=====================================================

The agent hunts BY ITSELF and genuinely branches on what it finds:

    seed alert
      -> think  (interpret last result, form hypothesis, choose next query)
      -> act    (run the query against real Elasticsearch)
      -> route  (conclude? hit the iteration cap? otherwise loop)

Two ways to run the SAME node functions:
  * run_plain() — a dependency-free while-loop. Used for the offline reliability
    test so you can prove it works with no Gemini key and no Docker.
  * run_graph() — the LangGraph StateGraph version for production. Same nodes,
    same logic, just wired as a graph.

The Pydantic-shaped decision is enforced by validate_decision(): if the brain
returns anything off-shape or an invalid template/params, we REJECT and retry.
That is the reliability seatbelt.

USAGE
  Offline reliability test (no deps needed, proves <=4 queries x10 runs):
      py -m agent
  Real Gemini brain on the live cluster (needs key + Docker + ingest):
      set GOOGLE_API_KEY=...      (Windows: setx, or $env:GOOGLE_API_KEY=...)
      py -m agent --live
  Real Gemini brain but offline data (needs key, no Docker):
      py -m agent --gemini-offline
"""
import argparse, sys
from queries import TEMPLATES

MAX_ITERS = 6          # beginner trap guard: never loop forever
TARGET_QUERIES = 4     # plan: must reach exfil in <=4 queries

# ---------------------------------------------------------------------------
# The menu the brain is constrained to (template_id, params, what it finds)
# ---------------------------------------------------------------------------
def build_menu():
    return "\n".join(f"  - {tid}  params={t['params']}  // {t['desc']}"
                     for tid, t in TEMPLATES.items())

# ---------------------------------------------------------------------------
# THE SEATBELT — reject anything that isn't a valid decision
# ---------------------------------------------------------------------------
def validate_decision(d):
    if not isinstance(d, dict):
        raise ValueError("decision is not an object")
    for f in ("interpretation", "next_hypothesis"):
        if not isinstance(d.get(f), str) or not d[f].strip():
            raise ValueError(f"missing/empty '{f}'")
    if d.get("conclude"):
        return d
    tid = d.get("template_id")
    if tid not in TEMPLATES:
        raise ValueError(f"invalid template_id '{tid}'")
    need = set(TEMPLATES[tid]["params"])
    got = set((d.get("params") or {}).keys())
    if need != got:
        raise ValueError(f"{tid} needs params {sorted(need)}, got {sorted(got)}")
    return d

def decide_with_retry(llm, alert, history, menu, retries=2):
    last_err = None
    for _ in range(retries + 1):
        try:
            return validate_decision(llm.decide(alert, history, menu))
        except Exception as e:
            last_err = e            # on a bad shape, loop and ask again
    raise ValueError(f"brain failed validation after retries: {last_err}")

# ---------------------------------------------------------------------------
# NODES (shared by both runners)
# ---------------------------------------------------------------------------
def think_node(state):
    d = decide_with_retry(state["llm"], state["alert"], state["history"], state["menu"])
    state["decision"] = d
    state["transcript"].append(("think", d["interpretation"], d.get("next_hypothesis"),
                                d.get("template_id"), d.get("params")))
    return state

def act_node(state):
    d = state["decision"]
    result = state["executor"].run(d["template_id"], d["params"])
    from agent_brains import summarize
    summary = summarize(result)
    state["history"].append({"template_id": d["template_id"], "params": d["params"],
                             "result": result, "summary": summary})
    state["transcript"].append(("act", d["template_id"], d["params"], summary))
    return state

def should_continue(state):
    if state["decision"].get("conclude"):
        return "end"
    if len(state["history"]) >= MAX_ITERS:        # hard cap
        return "end"
    return "act"

# ---------------------------------------------------------------------------
# RUNNER 1 — plain while-loop (no langgraph dependency)
# ---------------------------------------------------------------------------
def run_plain(llm, executor, alert, verbose=False):
    state = {"llm": llm, "executor": executor, "alert": alert, "menu": build_menu(),
             "history": [], "transcript": [], "decision": None}
    while True:
        think_node(state)
        if verbose:
            d = state["decision"]
            print(f"  THINK: {d['interpretation']}")
            if not d.get("conclude"):
                print(f"         -> next: {d['template_id']}({d['params']})")
        if should_continue(state) == "end":
            break
        act_node(state)
        if verbose:
            print(f"  ACT:   {state['history'][-1]['summary']}\n")
    return {"queries": len(state["history"]),
            "conclusion": state["decision"].get("conclusion") or state["decision"]["interpretation"],
            "history": state["history"], "transcript": state["transcript"]}

# ---------------------------------------------------------------------------
# RUNNER 2 — LangGraph StateGraph (production), same nodes
# ---------------------------------------------------------------------------
def run_graph(llm, executor, alert):
    from langgraph.graph import StateGraph, END
    g = StateGraph(dict)
    g.add_node("think", think_node)
    g.add_node("act", act_node)
    g.set_entry_point("think")
    g.add_conditional_edges("think", should_continue, {"act": "act", "end": END})
    g.add_edge("act", "think")
    app = g.compile()
    final = app.invoke({"llm": llm, "executor": executor, "alert": alert,
                        "menu": build_menu(), "history": [], "transcript": [],
                        "decision": None}, {"recursion_limit": MAX_ITERS * 2 + 2})
    return {"queries": len(final["history"]),
            "conclusion": final["decision"].get("conclusion") or final["decision"]["interpretation"],
            "history": final["history"], "transcript": final["transcript"]}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
ALERT = ("Weekly SOC review: 0 critical alerts fired this week. Treat as a "
         "retrospective hunt — assume a silent stolen-credential intrusion may "
         "have gone undetected. Find it or clear the environment.")

def reliability_test(runs=10):
    """Offline, mock brain: prove the loop reaches exfil in <=4 queries, repeatedly."""
    from agent_brains import MockLLM, OfflineExecutor
    ex = OfflineExecutor("logs.ndjson")
    ok = 0
    for i in range(runs):
        r = run_plain(MockLLM(), ex, ALERT)
        reached = "exfiltrat" in r["conclusion"].lower() or "exfil" in r["conclusion"].lower()
        good = reached and r["queries"] <= TARGET_QUERIES
        ok += good
        print(f"  run {i+1:2}: {r['queries']} queries | "
              f"{'PASS' if good else 'FAIL'} | {r['conclusion'][:70]}")
    print(f"\n  {ok}/{runs} runs reached the exfil in <= {TARGET_QUERIES} queries.")
    return ok == runs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="Gemini brain + Elasticsearch")
    ap.add_argument("--gemini-offline", action="store_true", help="Gemini brain + file data")
    ap.add_argument("--graph", action="store_true", help="use the LangGraph runner")
    ap.add_argument("--runs", type=int, default=10)
    args = ap.parse_args()

    if args.live or args.gemini_offline:
        from agent_brains import GeminiLLM, LiveExecutor, OfflineExecutor
        llm = GeminiLLM()
        ex = LiveExecutor() if args.live else OfflineExecutor("logs.ndjson")
        runner = run_graph if args.graph else run_plain
        print("=== LIVE HUNT ===")
        r = runner(llm, ex, ALERT) if runner is run_graph else run_plain(llm, ex, ALERT, verbose=True)
        print(f"\nReached conclusion in {r['queries']} queries:\n  {r['conclusion']}")
    else:
        print("=== OFFLINE RELIABILITY TEST (mock brain, file data) ===")
        passed = reliability_test(args.runs)
        sys.exit(0 if passed else 1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
BLOODHOUND — agent_brains.py
The two swappable pieces the reasoning loop plugs into:

  LLM       -> the brain that decides the next query.
               GeminiLLM (real, Pydantic-structured output) for production;
               MockLLM (deterministic, evidence-reactive) for offline testing.

  Executor  -> the hands that run a query.
               LiveExecutor (real Elasticsearch via queries.execute);
               OfflineExecutor (the NDJSON file, reusing the SAME analyzer
               functions queries.py uses live, so there's no logic drift).

Plus summarize(): turns a raw query result into the short text the brain reads,
so the model reasons about MEANING, not 23,000 rows of JSON.
"""
from __future__ import annotations
import json
from queries import TEMPLATES, _impossible_travel, _lateral_movement

# ===========================================================================
# Result summarizer — compact evidence the brain actually sees
# ===========================================================================
def _sample(e):
    keep = ["user.name", "host.name", "source.geo.city_name",
            "network.bytes", "destination.ip", "process.name", "@timestamp"]
    return " ".join(f"{k.split('.')[-1]}={e[k]}" for k in keep if k in e)

def summarize(result):
    tid, n = result["template_id"], result["count"]
    if result["kind"] == "analyze":
        lines = [f"{p[0].get('user.name')}: "
                 f"{p[0].get('source.geo.city_name', p[0].get('host.name'))} -> "
                 f"{p[1].get('source.geo.city_name', p[1].get('host.name'))}"
                 for p in result.get("sequences", [])[:4]]
        body = "; ".join(lines) if lines else "(none)"
        return f"{tid}: {n} match(es). {body}"
    evs = result.get("events", [])
    body = " | ".join(_sample(e) for e in evs[:3]) if evs else "(none)"
    return f"{tid}: {n} hit(s). {body}"

# ===========================================================================
# Executors
# ===========================================================================
class LiveExecutor:
    """Runs templates against real Elasticsearch."""
    def __init__(self, host="http://localhost:9200"):
        self.host = host
    def run(self, template_id, params):
        from queries import execute
        return execute(template_id, params, host=self.host)


class OfflineExecutor:
    """Runs templates against the NDJSON file. Reuses queries.py analyzers for
    the analyze templates so offline behaviour matches live exactly."""
    def __init__(self, path="logs.ndjson"):
        self.rows = [json.loads(l) for l in open(path) if l.strip()]

    def _net(self, r): return r.get("event.category") == "network"
    def _logon_ok(self, r):
        return r.get("event.action") == "logon" and r.get("event.outcome") == "success"

    def run(self, template_id, params):
        if template_id not in TEMPLATES:
            raise ValueError(f"unknown template_id '{template_id}'")
        kind = TEMPLATES[template_id]["kind"]
        rows = self.rows

        if template_id == "impossible_travel":
            seqs = _impossible_travel([r for r in rows if self._logon_ok(r)], params)
            return {"template_id": template_id, "kind": "analyze",
                    "count": len(seqs), "sequences": seqs}
        if template_id == "lateral_movement":
            seqs = _lateral_movement([r for r in rows if self._logon_ok(r)], params)
            return {"template_id": template_id, "kind": "analyze",
                    "count": len(seqs), "sequences": seqs}

        if template_id == "transfers_from_host":
            ev = [r for r in rows if self._net(r) and r.get("host.name") == params["host"]
                  and r.get("network.bytes", 0) >= params["min_bytes"]]
        elif template_id == "large_outbound_external":
            ev = [r for r in rows if self._net(r)
                  and r.get("network.bytes", 0) >= params["min_bytes"]
                  and not str(r.get("destination.ip", "")).startswith("10.")]
        elif template_id == "external_egress":
            ev = [r for r in rows if self._net(r)
                  and r.get("destination.ip") and not str(r["destination.ip"]).startswith("10.")]
        elif template_id == "auth_offhours":
            ev = [r for r in rows if self._logon_ok(r)
                  and int(r["@timestamp"][11:13]) <= params["max_hour"]]
        elif template_id == "auth_offhours_user":
            ev = [r for r in rows if self._logon_ok(r) and r.get("user.name") == params["user"]
                  and int(r["@timestamp"][11:13]) <= params["max_hour"]]
        elif template_id == "logons_for_user":
            ev = [r for r in rows if self._logon_ok(r) and r.get("user.name") == params["user"]]
        elif template_id == "logons_to_host":
            ev = [r for r in rows if self._logon_ok(r) and r.get("host.name") == params["host"]]
        elif template_id == "failures_for_user":
            ev = [r for r in rows if r.get("event.action") == "logon"
                  and r.get("event.outcome") == "failure" and r.get("user.name") == params["user"]]
        elif template_id == "encoded_powershell":
            ev = [r for r in rows if r.get("process.name") == "powershell.exe"
                  and "-enc" in str(r.get("process.command_line", ""))]
        elif template_id == "unusual_parent":
            ev = [r for r in rows if r.get("process.name") == params["proc"]
                  and r.get("process.parent.name") != params["expected_parent"]]
        elif template_id == "process_on_host":
            ev = [r for r in rows if r.get("event.category") == "process"
                  and r.get("host.name") == params["host"]]
        else:
            raise NotImplementedError(f"offline executor missing {template_id}")
        return {"template_id": template_id, "kind": kind, "count": len(ev), "events": ev}

# ===========================================================================
# Brains
# ===========================================================================
class MockLLM:
    """OFFLINE TEST HARNESS ONLY — not the real brain.
    It genuinely BRANCHES on the data it receives (so it proves the loop reacts
    to evidence), but its policy is hand-written, not learned. Use it to test the
    plumbing — graph wiring, validation, retries, the iteration cap — without
    spending Gemini calls. The real run uses GeminiLLM."""
    def __init__(self):
        self.suspects = []
        self.pivot = None

    def decide(self, alert, history, menu):
        if not history:
            return {"interpretation": "SOC shows zero alerts, but the brief says assume a "
                    "silent stolen-credential intrusion. Impossible travel is the cheapest tell.",
                    "next_hypothesis": "A user logged in from two distant places in a short window.",
                    "conclude": False, "template_id": "impossible_travel", "params": {"maxspan": "1h"}}
        last = history[-1]
        lt, res = last["template_id"], last["result"]

        if lt == "impossible_travel":
            users = sorted({p[0].get("user.name") for p in res.get("sequences", [])})
            if not users:
                return self._stop("No impossible travel anywhere — environment looks clean.")
            self.suspects = users
            return {"interpretation": f"Impossible travel for {users}. Could be VPN; a real "
                    "intruder also PIVOTS between hosts, a VPN user does not.",
                    "next_hypothesis": "One of these users moved laterally to a server.",
                    "conclude": False, "template_id": "lateral_movement", "params": {"maxspan": "2h"}}

        if lt == "lateral_movement":
            for p in res.get("sequences", []):
                u, dst = p[0].get("user.name"), p[1].get("host.name")
                if u in self.suspects and (str(dst).startswith("db-") or str(dst).startswith("app-")):
                    self.pivot = (u, dst)
            if not self.pivot:
                return self._stop("Impossible travel but no lateral movement — likely a benign VPN user.")
            u, dst = self.pivot
            return {"interpretation": f"{u} pivoted to {dst} — that's the real attacker, not the "
                    "VPN false positive.",
                    "next_hypothesis": f"Data was exfiltrated from {dst}.",
                    "conclude": False, "template_id": "transfers_from_host",
                    "params": {"host": dst, "min_bytes": 1_000_000_000}}

        if lt == "transfers_from_host":
            evs = res.get("events", [])
            # a big transfer to an INTERNAL host is a backup; to an EXTERNAL IP
            # it's exfiltration. Only the external one is the attack.
            exfil = [e for e in evs if not str(e.get("destination.ip", "")).startswith("10.")]
            if exfil:
                e = exfil[0]; gb = round(e.get("network.bytes", 0) / 1e9, 2)
                u, dst = self.pivot
                return self._stop(f"Patient zero: {u}. {gb}GB exfiltrated from {dst} to external "
                                  f"{e.get('destination.ip')}. (Internal backups on the same host "
                                  f"were correctly ignored.) Attack chain confirmed.")
            return self._stop("Transfers from the pivot host all went to internal backup "
                              "servers — no exfiltration. Likely benign.")

        return self._stop("Stopping.")

    def _stop(self, conclusion):
        return {"interpretation": conclusion, "next_hypothesis": "Investigation complete.",
                "conclude": True, "template_id": None, "params": {}, "conclusion": conclusion}


class GeminiLLM:
    """The real brain. Uses Gemini Flash with Pydantic-structured output so the
    response is forced into the Decision shape."""
    def __init__(self, model="gemini-2.0-flash", api_key=None):
        from google import genai
        self.genai = genai
        self.client = genai.Client(api_key=api_key) if api_key else genai.Client()
        self.model = model

    def decide(self, alert, history, menu):
        from google.genai import types
        from pydantic import BaseModel
        class Decision(BaseModel):           # the forced output shape
            interpretation: str
            next_hypothesis: str
            conclude: bool = False
            template_id: str | None = None
            params: dict = {}
            conclusion: str | None = None

        steps = "\n".join(
            f"  step {i+1}: ran {h['template_id']}({h['params']}) -> {h['summary']}"
            for i, h in enumerate(history)) or "  (no queries run yet)"
        prompt = (
            "You are a senior threat hunter investigating a possible silent intrusion.\n"
            f"ALERT: {alert}\n\n"
            f"AVAILABLE QUERY TEMPLATES (you may ONLY use these):\n{menu}\n\n"
            f"INVESTIGATION SO FAR:\n{steps}\n\n"
            "Interpret the MOST RECENT result, form the next hypothesis, and choose the "
            "single next template + params to test it. A VPN user shows impossible travel "
            "but NO lateral movement or exfil; a real attacker chains them. If you have "
            "confirmed patient zero AND exfiltration, set conclude=true and fill 'conclusion'. "
            "Respond ONLY as the structured object."
        )
        resp = self.client.models.generate_content(
            model=self.model, contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=Decision, temperature=0))
        return json.loads(resp.text)

    def map_mitre(self, catalogue, items, valid_ids):
        """Classify each observed behaviour to ONE technique ID from the fixed
        catalogue. temperature=0 + a constrained ID list keeps it consistent."""
        from google.genai import types
        from pydantic import BaseModel
        class Mapping(BaseModel):
            behaviour: str
            technique_id: str
            technique: str
        class MitreResult(BaseModel):
            mappings: list[Mapping]
        prompt = (
            "Map each observed behaviour to exactly ONE MITRE ATT&CK technique.\n"
            f"You may ONLY use these technique IDs: {valid_ids}\n\n"
            f"ATT&CK CATALOGUE:\n{catalogue}\n\n"
            f"OBSERVED BEHAVIOURS:\n{items}\n\n"
            "Return one mapping per behaviour. Use the most specific correct ID. "
            "Respond ONLY as the structured object."
        )
        resp = self.client.models.generate_content(
            model=self.model, contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=MitreResult, temperature=0))
        return json.loads(resp.text)["mappings"]

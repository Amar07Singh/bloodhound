#!/usr/bin/env python3
"""
BLOODHOUND — queries.py
The Day-3 deliverable in ONE file: the validated EQL template library + the
execute() function the rest of the system calls.

The model never writes raw EQL. It only picks a template_id and fills the
{placeholders}. Every template was validated once against the live index, so
every query the model produces is guaranteed valid syntax.

Use (after `docker compose up -d` and `python3 ingest.py`):
    from queries import execute
    r = execute("impossible_travel", {"maxspan": "1h"})
    print(r["count"])

Want to see the menu the model chooses from?  python3 queries.py
"""

from datetime import datetime

# --- analyzers: the cross-event comparisons EQL can't do, done reliably in
#     Python over events pulled by a bulletproof retrieval query --------------
def _span_seconds(span):
    # accept a bare number (seconds) — the LLM sometimes returns maxspan=60
    if isinstance(span, (int, float)):
        return int(span)
    span = str(span).strip()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if span and span[-1] in units:               # "1h", "30m", "90s"
        return int(span[:-1]) * units[span[-1]]
    return int(span)                              # plain numeric string -> seconds

def _adjacent_pairs(events, maxspan, differ_on):
    """Group by user, sort by time, return adjacent same-user pairs that are
    within maxspan AND differ on the given field (country or host)."""
    secs = _span_seconds(maxspan)
    by_user = {}
    for e in events:
        by_user.setdefault(e.get("user.name"), []).append(e)
    pairs = []
    for evs in by_user.values():
        evs.sort(key=lambda r: r["@timestamp"])
        for i in range(len(evs) - 1):
            a, b = evs[i], evs[i + 1]
            ta = datetime.fromisoformat(a["@timestamp"].replace("Z", "+00:00"))
            tb = datetime.fromisoformat(b["@timestamp"].replace("Z", "+00:00"))
            if (tb - ta).total_seconds() <= secs and a.get(differ_on) != b.get(differ_on):
                pairs.append([a, b])
    return pairs

def _impossible_travel(events, params):
    return _adjacent_pairs(events, params["maxspan"], "source.geo.country_name")

def _lateral_movement(events, params):
    return _adjacent_pairs(events, params["maxspan"], "host.name")

ANALYZERS = {"_impossible_travel": _impossible_travel,
             "_lateral_movement": _lateral_movement}


TEMPLATES = {
    # ---------------- AUTHENTICATION ----------------
    "auth_offhours": {
        "kind": "single", "params": ["max_hour"],
        "desc": "Successful logons in the small hours (0..max_hour).",
        "eql": ('authentication where event.action == "logon" '
                'and event.outcome == "success" and hour_of_day <= {max_hour}'),
    },
    "auth_offhours_user": {
        "kind": "single", "params": ["user", "max_hour"],
        "desc": "Off-hours successful logons for ONE user.",
        "eql": ('authentication where event.action == "logon" '
                'and event.outcome == "success" and user.name == "{user}" '
                'and hour_of_day <= {max_hour}'),
    },
    "logons_for_user": {
        "kind": "single", "params": ["user"],
        "desc": "All successful logons for a user (inspect geo spread).",
        "eql": ('authentication where event.action == "logon" '
                'and event.outcome == "success" and user.name == "{user}"'),
    },
    "logons_to_host": {
        "kind": "single", "params": ["host"],
        "desc": "Who successfully logged on to a given host.",
        "eql": ('authentication where event.action == "logon" '
                'and event.outcome == "success" and host.name == "{host}"'),
    },
    "failures_for_user": {
        "kind": "single", "params": ["user"],
        "desc": "Failed logons for a user (credential guessing / spray).",
        "eql": ('authentication where event.action == "logon" '
                'and event.outcome == "failure" and user.name == "{user}"'),
    },
    "failed_then_success": {
        "kind": "sequence", "params": ["maxspan"],
        "desc": "A failed logon quickly followed by a success (same user).",
        "eql": ('sequence by user.name with maxspan={maxspan}\n'
                '  [ authentication where event.action == "logon" and event.outcome == "failure" ]\n'
                '  [ authentication where event.action == "logon" and event.outcome == "success" ]'),
    },
    # These two need to compare a field ACROSS events for INEQUALITY (different
    # country / different host). EQL genuinely cannot express that, and bolting a
    # post-filter onto a generic sequence proved unreliable on the live cluster.
    # So they use kind="analyze": pull the relevant events with a bulletproof
    # Query-DSL retrieval (paginated, never capped), then do the cross-event
    # comparison in Python. This is the reliable pattern.
    "impossible_travel": {
        "kind": "analyze", "params": ["maxspan"], "analyzer": "_impossible_travel",
        "pull": {"event.action": "logon", "event.outcome": "success"},
        "desc": "Same user, two successful logons within maxspan, DIFFERENT countries.",
    },
    "lateral_movement": {
        "kind": "analyze", "params": ["maxspan"], "analyzer": "_lateral_movement",
        "pull": {"event.action": "logon", "event.outcome": "success"},
        "desc": "Same user logging on to a DIFFERENT host within maxspan (pivot).",
    },

    # ---------------- NETWORK ----------------
    "large_outbound_external": {
        "kind": "single", "params": ["min_bytes"],
        "desc": "Large transfers leaving the network (destination NOT 10.0.0.0/8).",
        "eql": ('network where network.bytes >= {min_bytes} '
                'and not cidrMatch(destination.ip, "10.0.0.0/8")'),
    },
    "transfers_from_host": {
        "kind": "single", "params": ["host", "min_bytes"],
        "desc": "Large transfers originating from a specific host.",
        "eql": 'network where host.name == "{host}" and network.bytes >= {min_bytes}',
    },
    "external_egress": {
        "kind": "single", "params": [],
        "desc": "Any flow whose destination is outside the corporate range.",
        "eql": 'network where not cidrMatch(destination.ip, "10.0.0.0/8")',
    },

    # ---------------- PROCESS ----------------
    "encoded_powershell": {
        "kind": "single", "params": [],
        "desc": "PowerShell launched with an encoded command (Living-off-the-Land).",
        "eql": ('process where process.name == "powershell.exe" '
                'and process.command_line : "*-enc*"'),
    },
    "unusual_parent": {
        "kind": "single", "params": ["proc", "expected_parent"],
        "desc": "A process spawned by an unexpected parent.",
        "eql": ('process where process.name == "{proc}" '
                'and not process.parent.name == "{expected_parent}"'),
    },
    "process_on_host": {
        "kind": "single", "params": ["host"],
        "desc": "What processes ran on a given host (e.g. the database server).",
        "eql": 'process where host.name == "{host}"',
    },
}

INDEX = "bloodhound-logs"
_es = None

def _client(host):
    global _es
    if _es is None:
        from elasticsearch import Elasticsearch     # lazy: templates load w/o ES
        _es = Elasticsearch(host, request_timeout=60)
    return _es

def _flatten(src):
    out = {}
    def walk(prefix, obj):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            walk(key, v) if isinstance(v, dict) else out.__setitem__(key, v)
    walk("", src)
    return out

def execute(template_id, params=None, *, host="http://localhost:9200",
            size=100, time_range=None):
    """Run one validated template. Returns {template_id, kind, eql, count, ...}."""
    params = params or {}
    if template_id not in TEMPLATES:
        raise ValueError(f"unknown template_id '{template_id}'")
    tpl = TEMPLATES[template_id]
    if set(tpl["params"]) != set(params):
        raise ValueError(f"{template_id} needs params {sorted(tpl['params'])}, "
                         f"got {sorted(params)}")

    out = {"template_id": template_id, "kind": tpl["kind"]}

    # ----- pull-then-analyze: reliable retrieval + Python cross-event logic ----
    if tpl["kind"] == "analyze":
        from elasticsearch import helpers
        dsl = {"query": {"bool": {"filter":
               [{"term": {k: v}} for k, v in tpl["pull"].items()]}}}
        events = [_flatten(h["_source"])
                  for h in helpers.scan(_client(host), index=INDEX, query=dsl)]
        seqs = ANALYZERS[tpl["analyzer"]](events, params)
        out["count"], out["sequences"], out["pulled"] = len(seqs), seqs, len(events)
        return out

    # ----- EQL templates -----
    query = tpl["eql"].format(**params)
    body = {"query": query, "size": size}
    if time_range:
        body["filter"] = {"range": {"@timestamp": time_range}}
    resp = _client(host).eql.search(index=INDEX, body=body)
    hits = resp.get("hits", {})
    out["eql"] = query
    if tpl["kind"] == "single":
        events = [_flatten(e["_source"]) for e in hits.get("events", [])]
        out["count"], out["events"] = len(events), events
    else:  # sequence (e.g. failed_then_success) — fixed predicates, no inequality
        seqs = [[_flatten(e["_source"]) for e in s.get("events", [])]
                for s in hits.get("sequences", [])]
        out["count"], out["sequences"] = len(seqs), seqs
    return out


if __name__ == "__main__":
    # No cluster needed: just print the menu the model is constrained to.
    print(f"{len(TEMPLATES)} validated templates:\n")
    for tid, t in TEMPLATES.items():
        print(f"  {tid:26} {t['kind']:9} params={t['params']}")
        print(f"  {'':26} {t['desc']}")

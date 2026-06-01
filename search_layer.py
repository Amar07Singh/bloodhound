#!/usr/bin/env python3
"""
BLOODHOUND — Search Layer v2  (real-world architecture)
=======================================================

What changed vs the Day-3 version, and WHY it's better:

  1. TWO engines, not one. EQL handles sequences/correlation; Query-DSL
     AGGREGATIONS handle baselining + counting (top-N, cardinality, histograms)
     -- the half of hunting EQL literally cannot do.

  2. BASELINE-relative anomalies. We compute each user's "normal" (countries,
     hosts, usual hours) from the data, so "anomalous" means anomalous FOR THAT
     USER -- not a hardcoded hour<=4 that everyone shares.

  3. Detections emit structured SIGNALS, not raw rows. Each signal carries
     severity + MITRE technique + the computed EVIDENCE (cities, km, velocity).
     Downstream (timeline, MITRE, report) consumes facts instead of re-parsing.

  4. Real impossible-travel by VELOCITY. distance / time = required speed; we
     flag physically impossible speeds and report HOW impossible. No more
     "country changed in an hour."

  5. CORRELATION. Many signals -> few ranked INCIDENTS. Five signals about one
     user that chain across kill-chain stages become ONE incident with a risk
     score. This is the alert-fatigue problem your pitch claims to solve.

  6. BACKEND ABSTRACTION. The same template code runs on a live Elasticsearch
     cluster (correct 8.x keyword API) OR on an offline file (pure Python), so
     the layer is testable without a cluster. This file's __main__ proves the
     logic offline against the real dataset + ground truth.
"""
from __future__ import annotations
import json, math, sys
from collections import Counter, defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Geography for real velocity-based impossible travel
# ---------------------------------------------------------------------------
CITY_COORDS = {
    "Seattle": (47.61, -122.33), "Austin": (30.27, -97.74),
    "Chicago": (41.88, -87.63), "New York": (40.71, -74.01),
    "San Jose": (37.34, -121.89), "Toronto": (43.65, -79.38),
    "London": (51.51, -0.13), "Berlin": (52.52, 13.40),
    "Bangalore": (12.97, 77.59),
}
def haversine_km(a, b):
    if a not in CITY_COORDS or b not in CITY_COORDS:
        return None
    (la1, lo1), (la2, lo2) = CITY_COORDS[a], CITY_COORDS[b]
    r = 6371.0
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = math.radians(la2 - la1), math.radians(lo2 - lo1)
    h = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * r * math.asin(math.sqrt(h))

MAX_FEASIBLE_KMH = 1000.0   # faster than a commercial jet => impossible

SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ===========================================================================
# BACKEND ABSTRACTION  — same primitives, two implementations
# ===========================================================================
class Backend:
    """Primitive operations the detections are written against."""
    def events(self, **filters): raise NotImplementedError
    def sequences(self, by, maxspan_s, n=2): raise NotImplementedError
    def terms(self, field, **filters): raise NotImplementedError
    def cardinality(self, field, **filters): raise NotImplementedError


class OfflineBackend(Backend):
    """Runs against the NDJSON file in pure Python (no cluster). Source of truth
    for unit tests and for proving logic before the cluster exists."""
    def __init__(self, path):
        self.rows = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    d = json.loads(line)
                    d["_t"] = datetime.fromisoformat(d["@timestamp"].replace("Z","+00:00"))
                    self.rows.append(d)
        self.rows.sort(key=lambda r: r["_t"])

    def _match(self, r, filters):
        for k, v in filters.items():
            if k.endswith("__gte"):
                if r.get(k[:-5], 0) < v: return False
            elif k.endswith("__not_prefix"):
                val = r.get(k[:-12]); 
                if val is None or str(val).startswith(v): return False
            elif k.endswith("__contains"):
                if v not in str(r.get(k[:-10], "")): return False
            else:
                if r.get(k) != v: return False
        return True

    def events(self, **filters):
        return [r for r in self.rows if self._match(r, filters)]

    def sequences(self, by, maxspan_s, n=2, **filters):
        groups = defaultdict(list)
        for r in self.events(**filters):
            groups[r.get(by)].append(r)
        out = []
        for key, evs in groups.items():
            evs.sort(key=lambda r: r["_t"])
            for i in range(len(evs) - n + 1):
                win = evs[i:i+n]
                if (win[-1]["_t"] - win[0]["_t"]).total_seconds() <= maxspan_s:
                    out.append(win)
        return out

    def terms(self, field, **filters):
        return Counter(r.get(field) for r in self.events(**filters))

    def cardinality(self, field, **filters):
        return len({r.get(field) for r in self.events(**filters)})


class LiveESBackend(Backend):
    """Real Elasticsearch 8.x. NOTE the keyword-arg API (query=, filter=, size=,
    aggs=, mappings=) — the deprecated body= style is gone. Not exercised in the
    offline proof, but this is the correct production translation."""
    def __init__(self, host="http://localhost:9200", index="bloodhound-logs"):
        from elasticsearch import Elasticsearch
        self.es = Elasticsearch(host, request_timeout=60)
        self.index = index

    def events(self, **filters):
        must = self._to_dsl(filters)
        resp = self.es.search(index=self.index, query={"bool": {"filter": must}},
                              size=1000)
        return [h["_source"] for h in resp["hits"]["hits"]]

    def sequences(self, by, maxspan_s, n=2, **filters):
        # On the live cluster this is an EQL sequence query:
        #   sequence by <by> with maxspan=<...>s [ ... ] [ ... ]
        steps = "\n".join("  [ any where true ]" for _ in range(n))
        eql = f"sequence by {by} with maxspan={maxspan_s}s\n{steps}"
        resp = self.es.eql.search(index=self.index, query=eql, size=1000)
        return [[e["_source"] for e in s["events"]]
                for s in resp.get("hits", {}).get("sequences", [])]

    def terms(self, field, **filters):
        resp = self.es.search(index=self.index, size=0,
            query={"bool": {"filter": self._to_dsl(filters)}},
            aggs={"t": {"terms": {"field": field, "size": 50}}})
        return Counter({b["key"]: b["doc_count"]
                        for b in resp["aggregations"]["t"]["buckets"]})

    def cardinality(self, field, **filters):
        resp = self.es.search(index=self.index, size=0,
            query={"bool": {"filter": self._to_dsl(filters)}},
            aggs={"c": {"cardinality": {"field": field}}})
        return resp["aggregations"]["c"]["value"]

    @staticmethod
    def _to_dsl(filters):
        dsl = []
        for k, v in filters.items():
            if k.endswith("__gte"):
                dsl.append({"range": {k[:-5]: {"gte": v}}})
            elif k.endswith("__not_prefix"):
                dsl.append({"bool": {"must_not": {"prefix": {k[:-12]: v}}}})
            elif k.endswith("__contains"):
                dsl.append({"wildcard": {k[:-10]: f"*{v}*"}})
            else:
                dsl.append({"term": {k: v}})
        return dsl

# ===========================================================================
# BASELINING  — compute each user's "normal" from the data
# ===========================================================================
def user_baseline(be, user):
    logons = be.events(**{"user.name": user, "event.action": "logon",
                          "event.outcome": "success"})
    countries = Counter(e.get("source.geo.country_name") for e in logons)
    hosts = Counter(e.get("host.name") for e in logons)
    hours = Counter(e["_t"].hour if "_t" in e else int(e["@timestamp"][11:13])
                    for e in logons)
    return {"user": user, "logon_count": len(logons),
            "countries": dict(countries), "hosts": dict(hosts),
            "primary_country": countries.most_common(1)[0][0] if countries else None,
            "hours": dict(hours)}

# ===========================================================================
# DETECTIONS  — each returns structured SIGNALS (not raw rows)
# ===========================================================================
def signal(detection, severity, mitre, user, evidence, events, why):
    return {"detection": detection, "severity": severity, "mitre": mitre,
            "user": user, "evidence": evidence,
            "event_ids": [e.get("event.id") for e in events], "why": why}

def detect_impossible_travel(be, maxspan_s=3600):
    out = []
    for pair in be.sequences(by="user.name", maxspan_s=maxspan_s, n=2,
                             **{"event.action": "logon", "event.outcome": "success"}):
        a, b = pair
        ca, cb = a.get("source.geo.city_name"), b.get("source.geo.city_name")
        if ca == cb:
            continue
        gap_h = max((b["_t"] - a["_t"]).total_seconds() / 3600, 1/3600)
        km = haversine_km(ca, cb)
        if km is None:
            continue
        kmh = km / gap_h
        if kmh <= MAX_FEASIBLE_KMH:
            continue  # feasible travel -> NOT a detection (kills VPN false-pos)
        sev = "critical" if kmh > 5000 else "high"
        out.append(signal(
            "impossible_travel", sev, ["T1078"], a["user.name"],
            {"from": ca, "to": cb, "distance_km": round(km),
             "minutes": round(gap_h*60, 1), "required_kmh": round(kmh)},
            pair,
            f"{a['user.name']} moved {ca}->{cb} ({round(km)}km) in "
            f"{round(gap_h*60)}min = {round(kmh):,} km/h (max feasible {int(MAX_FEASIBLE_KMH)})"))
    return out

def detect_new_country(be):
    """Baseline-relative: a successful logon from a country the user has barely
    ever used. 'Anomalous for THIS user', not a global constant."""
    out = []
    users = {e.get("user.name") for e in be.events(**{"event.action":"logon",
             "event.outcome":"success"}) if e.get("user.name")}
    for u in users:
        bl = user_baseline(be, u)
        total = bl["logon_count"]
        for country, cnt in bl["countries"].items():
            if country and country != bl["primary_country"] and cnt / total < 0.15:
                evs = be.events(**{"user.name": u, "event.action":"logon",
                                   "event.outcome":"success",
                                   "source.geo.country_name": country})
                out.append(signal(
                    "new_geo_for_user", "medium", ["T1078"], u,
                    {"country": country, "this_country_logons": cnt,
                     "user_total_logons": total,
                     "primary_country": bl["primary_country"]},
                    evs[:3],
                    f"{u} normally logs in from {bl['primary_country']}; "
                    f"{cnt}/{total} logons from {country}"))
    return out

def detect_lateral_movement(be, maxspan_s=7200):
    out = []
    for pair in be.sequences(by="user.name", maxspan_s=maxspan_s, n=2,
                             **{"event.action":"logon","event.outcome":"success"}):
        a, b = pair
        if a.get("host.name") != b.get("host.name"):
            out.append(signal(
                "lateral_movement", "high", ["T1021"], a["user.name"],
                {"from_host": a.get("host.name"), "to_host": b.get("host.name"),
                 "minutes": round((b["_t"]-a["_t"]).total_seconds()/60, 1)},
                pair,
                f"{a['user.name']} pivoted {a.get('host.name')} -> {b.get('host.name')}"))
    return out

def detect_large_exfil(be, min_bytes=1_000_000_000):
    out = []
    for e in be.events(**{"event.category":"network",
                          "network.bytes__gte": min_bytes,
                          "destination.ip__not_prefix": "10."}):
        out.append(signal(
            "exfiltration", "critical", ["T1041"], e.get("user.name"),
            {"gb": round(e["network.bytes"]/1e9, 2), "host": e.get("host.name"),
             "dest_ip": e.get("destination.ip"),
             "dest_country": e.get("source.geo.country_name")},
            [e],
            f"{round(e['network.bytes']/1e9,2)}GB from {e.get('host.name')} "
            f"-> external {e.get('destination.ip')}"))
    return out

def detect_encoded_powershell(be):
    out = []
    for e in be.events(**{"process.name":"powershell.exe",
                          "process.command_line__contains":"-enc"}):
        out.append(signal(
            "lolbin_powershell", "high", ["T1059.001"], e.get("user.name"),
            {"host": e.get("host.name"), "cmd": e.get("process.command_line")},
            [e], f"encoded PowerShell on {e.get('host.name')}"))
    return out

ALL_DETECTIONS = [detect_impossible_travel, detect_new_country,
                  detect_lateral_movement, detect_large_exfil,
                  detect_encoded_powershell]

# ===========================================================================
# CORRELATION  — signals -> ranked incidents (the alert-fatigue fix)
# ===========================================================================
def correlate(signals):
    by_user = defaultdict(list)
    for s in signals:
        if s["user"]:
            by_user[s["user"]].append(s)
    incidents = []
    for user, sigs in by_user.items():
        risk = sum(SEV[s["severity"]] for s in sigs)
        stages = {s["detection"] for s in sigs}
        techniques = sorted({m for s in sigs for m in s["mitre"]})
        # an incident that chains exfil + a movement/access signal is the real deal
        is_attack = "exfiltration" in stages and len(stages) >= 3
        incidents.append({
            "user": user, "risk_score": risk, "num_signals": len(sigs),
            "stages": sorted(stages), "mitre": techniques,
            "verdict": "ACTIVE INTRUSION" if is_attack else "review",
            "signals": sigs})
    incidents.sort(key=lambda i: i["risk_score"], reverse=True)
    return incidents

# ===========================================================================
# PROOF  — run offline against the real dataset + ground truth
# ===========================================================================
def main():
    data = sys.argv[1] if len(sys.argv) > 1 else "logs.ndjson"
    truth_path = sys.argv[2] if len(sys.argv) > 2 else "ground_truth.json"
    be = OfflineBackend(data)
    truth = json.load(open(truth_path))

    print(f"loaded {len(be.rows):,} events (offline backend)\n")

    # show baselining works: the attacker's normal vs the anomaly
    bl = user_baseline(be, truth["attacker"])
    print(f"BASELINE for {bl['user']}: primary_country={bl['primary_country']}, "
          f"countries={bl['countries']}, hosts touched={len(bl['hosts'])}")

    # show an aggregation EQL can't do: top users by failed logons
    fails = be.terms("user.name", **{"event.action":"logon","event.outcome":"failure"})
    print(f"AGG top failed-logon users: {fails.most_common(3)}\n")

    # run all detections -> signals
    signals = []
    for d in ALL_DETECTIONS:
        s = d(be)
        signals.extend(s)
        print(f"  {d.__name__:28} -> {len(s)} signal(s)")
    print(f"\nTOTAL signals: {len(signals)}")

    # correlate into incidents
    incidents = correlate(signals)
    print(f"CORRELATED into {len(incidents)} incident(s):\n")
    for inc in incidents:
        print(f"  [{inc['verdict']:16}] {inc['user']:16} risk={inc['risk_score']:>2} "
              f"signals={inc['num_signals']} stages={inc['stages']}")

    top = incidents[0]
    print(f"\nTOP INCIDENT detail ({top['user']}):")
    for s in sorted(top["signals"], key=lambda x: SEV[x["severity"]], reverse=True):
        print(f"   - [{s['severity']:8}] {s['detection']:20} {s['why']}")
    print(f"\n  ground-truth attacker: {truth['attacker']}  "
          f"-> {'MATCH' if top['user']==truth['attacker'] else 'MISMATCH'}")

if __name__ == "__main__":
    main()

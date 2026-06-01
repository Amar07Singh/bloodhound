#!/usr/bin/env python3
"""
BLOODHOUND — Synthetic Attack Dataset Generator  v2
===================================================

Why v2 beats v1, in one idea:
    v1 fired independent random events. v2 models ENTITIES (users with a stable
    identity) and SESSIONS (login -> correlated activity -> logout). Because each
    user now has a believable BASELINE, the attacker's behaviour actually stands
    out by *violating* that baseline -- which is the whole point of threat hunting.

Key upgrades over v1:
  1. Stable per-user identity (home IP, home city, primary host, role apps).
  2. Session-based activity -> realistic event ratios + correlation IDs.
  3. Enriched ECS: event.outcome, destination.ip/port, geo.city_name,
     process.parent.name, process.command_line, session.id, *.bytes.
  4. The attack is spread across 6 days (real dwell time) and is MULTI-HOP
     (workstation -> app server -> database) so the lateral-movement graph
     has real edges.
  5. The exfil has a real external destination IP -> "2.3GB out to X" story.
  6. Weekend dip in traffic; attacker strikes the quiet weekend night.
  7. 2 decoy "near-miss" users (one suspicious trait each, but innocent) so the
     agent has to DISCRIMINATE, not just grep for weird.
  8. A separate ground_truth.json (attack event IDs + MITRE + timeline) that the
     agent NEVER sees -- used to validate the agent and to demo with confidence.

Run:
    python3 generate_logs_v2.py                  # ~500k events + ground truth
    python3 generate_logs_v2.py --events 120000  # smaller / faster
    python3 generate_logs_v2.py --clean          # control set, NO attack

Dependencies: NONE (pure standard library).
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
DEFAULT_EVENTS = 500_000
NUM_USERS = 200
DAYS = 7                       # full week -> contains a weekend
START = datetime(2025, 5, 19, 0, 0, 0, tzinfo=timezone.utc)  # Monday

ATTACKER = "mark.chen"
EXFIL_BYTES = 2_470_000_000    # ~2.30 GB  (bytes / 1024^3)
EXTERNAL_C2_IP = "185.220.101.47"   # the exfil destination (looks external/hostile)
EXFIL_DEST_COUNTRY = "Netherlands"

# ---------------------------------------------------------------------------
# IDENTITY BUILDING BLOCKS
# ---------------------------------------------------------------------------
FIRST = ["james", "mary", "john", "patricia", "robert", "jennifer", "michael",
         "linda", "william", "elizabeth", "david", "barbara", "richard", "susan",
         "joseph", "jessica", "thomas", "sarah", "charles", "karen", "mark",
         "nancy", "daniel", "lisa", "paul", "betty", "kevin", "sandra", "brian",
         "ashley", "george", "kimberly", "edward", "emily", "ronald", "donna",
         "wei", "amir", "priya", "sofia", "diego", "yuki", "ahmed", "olga", "raj"]
LAST = ["smith", "johnson", "williams", "brown", "jones", "garcia", "miller",
        "davis", "rodriguez", "martinez", "lopez", "gonzalez", "wilson",
        "anderson", "taylor", "moore", "jackson", "lee", "perez", "thompson",
        "white", "harris", "clark", "lewis", "walker", "young", "king", "wright",
        "torres", "nguyen", "hill", "chen", "patel", "kim", "singh", "khan",
        "wang", "kumar", "shah", "reed"]

# City -> (country, IP /16 prefix). Users get a stable home IP from their city.
CITIES = {
    "Seattle":     ("United States", "73.181"),
    "Austin":      ("United States", "70.114"),
    "Chicago":     ("United States", "98.220"),
    "New York":    ("United States", "74.88"),
    "San Jose":    ("United States", "50.0"),
    "Toronto":     ("Canada",        "99.224"),
    "London":      ("United Kingdom","81.149"),
    "Berlin":      ("Germany",       "91.13"),
    "Bangalore":   ("India",         "117.96"),
}

WORKSTATIONS = [f"ws-{i:04d}" for i in range(1, 161)]
APP_SERVERS  = [f"app-prod-{i:02d}" for i in range(1, 9)]
DB_SERVERS   = ["db-prod-01", "db-prod-02", "db-prod-03"]
FILE_SERVERS = ["fs-01", "fs-02"]

# Role -> the processes that role normally runs (baseline behaviour).
ROLE_APPS = {
    "office":   ["outlook.exe", "excel.exe", "winword.exe", "chrome.exe",
                 "teams.exe", "explorer.exe"],
    "engineer": ["code.exe", "python.exe", "node.exe", "chrome.exe",
                 "cmd.exe", "git.exe", "docker.exe"],
    "dba":      ["sqlservr.exe", "ssms.exe", "powershell.exe", "cmd.exe",
                 "outlook.exe"],
    "sales":    ["chrome.exe", "outlook.exe", "salesforce.exe", "excel.exe",
                 "teams.exe"],
}
PARENTS = {"chrome.exe": "explorer.exe", "cmd.exe": "explorer.exe",
           "powershell.exe": "explorer.exe", "python.exe": "code.exe",
           "node.exe": "code.exe"}

INTERNAL = "10.0.{}.{}"

def internal_ip():
    return INTERNAL.format(random.randint(1, 40), random.randint(1, 254))

def home_ip(prefix):
    """A stable-ish public IP inside the user's home /16."""
    return f"{prefix}.{random.randint(0,255)}.{random.randint(1,254)}"

def new_id():
    return uuid.uuid4().hex[:16]

# ---------------------------------------------------------------------------
# USER PROFILES  (the baseline that makes anomalies meaningful)
# ---------------------------------------------------------------------------
def build_profiles():
    profiles, seen = [], set()
    while len(profiles) < NUM_USERS:
        name = f"{random.choice(FIRST)}.{random.choice(LAST)}"
        if name in seen:
            continue
        seen.add(name)
        city = random.choice(list(CITIES.keys()))
        country, prefix = CITIES[city]
        role = random.choice(list(ROLE_APPS.keys()))
        profiles.append({
            "name": name,
            "user_id": f"S-1-5-{random.randint(1000,9999)}",
            "city": city, "country": country, "ip_prefix": prefix,
            "host": random.choice(WORKSTATIONS),
            "host_id": new_id(),
            "role": role,
            "start_hour": random.randint(7, 10),     # personal work rhythm
            "end_hour": random.randint(16, 19),
            "night_owl": random.random() < 0.15,      # legit late workers (noise)
        })

    # Force the attacker to be an ordinary Seattle office user with a CLEAN,
    # stable baseline. The whole hunt depends on this baseline existing.
    profiles[0] = {
        "name": ATTACKER, "user_id": "S-1-5-2207",
        "city": "Seattle", "country": "United States", "ip_prefix": "73.181",
        "host": "ws-0042", "host_id": new_id(), "role": "office",
        "start_hour": 9, "end_hour": 17, "night_owl": False,
    }
    return profiles

# ---------------------------------------------------------------------------
# EVENT FACTORY
# ---------------------------------------------------------------------------
def iso(ts):
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def ev(ts, action, category, outcome, prof, host, src_ip, country, city,
       *, net=0, dst_ip=None, dst_port=None, process=None, parent=None,
       cmdline=None, session=None):
    e = {
        "@timestamp": iso(ts),
        "event.id": new_id(),
        "event.dataset": {"authentication": "system.auth",
                          "process": "system.process",
                          "network": "system.netflow"}[category],
        "event.action": action,
        "event.category": category,
        "event.outcome": outcome,
        "source.ip": src_ip,
        "source.geo.country_name": country,
        "source.geo.city_name": city,
        "user.name": prof["name"],
        "user.id": prof["user_id"],
        "host.name": host,
        "host.id": prof["host_id"],
        "network.bytes": net,
        "session.id": session or new_id(),
    }
    if dst_ip:
        e["destination.ip"] = dst_ip
        e["destination.port"] = dst_port or 443
    if process:
        e["process.name"] = process
        e["process.parent.name"] = parent or PARENTS.get(process, "explorer.exe")
        if cmdline:
            e["process.command_line"] = cmdline
    return e

# ---------------------------------------------------------------------------
# NORMAL SESSION  (login -> correlated activity -> logout)
# ---------------------------------------------------------------------------
def day_is_weekend(day_idx):
    return (START + timedelta(days=day_idx)).weekday() >= 5  # Sat/Sun

def session_start_time(prof, day_idx):
    weekend = day_is_weekend(day_idx)
    if prof["night_owl"] and random.random() < 0.4:
        hour = random.choice([20, 21, 22, 23, 0, 1])
    elif weekend:
        hour = random.randint(10, 16) if random.random() < 0.3 else None
        if hour is None:
            return None  # most people don't work weekends -> traffic dip
    else:
        hour = random.randint(prof["start_hour"], prof["end_hour"])
    return START + timedelta(days=day_idx, hours=hour,
                             minutes=random.randint(0, 59),
                             seconds=random.randint(0, 59))

def make_session(prof, day_idx, rows):
    start = session_start_time(prof, day_idx)
    if start is None:
        return
    sid = new_id()
    src = home_ip(prof["ip_prefix"])
    # occasional fat-fingered password before a successful login (realistic)
    if random.random() < 0.18:
        rows.append(ev(start - timedelta(seconds=random.randint(5, 90)),
                       "logon", "authentication", "failure", prof, prof["host"],
                       src, prof["country"], prof["city"], session=sid))
    rows.append(ev(start, "logon", "authentication", "success", prof,
                   prof["host"], src, prof["country"], prof["city"], session=sid))

    # activity burst on the user's own host, same session id
    t = start
    apps = ROLE_APPS[prof["role"]]
    for _ in range(random.randint(8, 30)):
        t += timedelta(minutes=random.randint(1, 25))
        if random.random() < 0.5:
            p = random.choice(apps)
            rows.append(ev(t, "process_started", "process", "success", prof,
                           prof["host"], internal_ip(), prof["country"],
                           prof["city"], process=p, session=sid))
        else:
            rows.append(ev(t, "network_flow", "network", "success", prof,
                           prof["host"], internal_ip(), prof["country"],
                           prof["city"], net=random.randint(2_000, 4_000_000),
                           dst_ip=internal_ip(), dst_port=random.choice([443,80,445]),
                           session=sid))
    # logout
    rows.append(ev(t + timedelta(minutes=random.randint(2, 30)),
                   "logoff", "authentication", "success", prof, prof["host"],
                   src, prof["country"], prof["city"], session=sid))

# ---------------------------------------------------------------------------
# SERVICE NOISE: nightly backups (legit GIGABYTE transfers) + vuln scans
# ---------------------------------------------------------------------------
def svc_profile(name):
    return {"name": name, "user_id": "S-1-5-18", "city": "Seattle",
            "country": "United States", "ip_prefix": "10.0",
            "host": "n/a", "host_id": new_id(), "role": "office"}

def add_backups(rows):
    p = svc_profile("svc.backup")
    for d in range(DAYS):
        for _ in range(random.randint(4, 7)):
            host = random.choice(DB_SERVERS + FILE_SERVERS)
            t = START + timedelta(days=d, hours=1, minutes=random.randint(0, 59))
            rows.append(ev(t, "network_flow", "network", "success", p, host,
                           "10.0.50.10", "United States", "Seattle",
                           net=random.randint(1_000_000_000, 4_000_000_000),
                           dst_ip="10.0.60.20", dst_port=443,
                           process="backup-agent.exe", session=new_id()))

def add_scans(rows):
    p = svc_profile("svc.scanner")
    for d in range(DAYS):
        for _ in range(random.randint(30, 60)):
            host = random.choice(WORKSTATIONS + APP_SERVERS + DB_SERVERS)
            t = START + timedelta(days=d, hours=random.choice([2, 3, 22, 23]),
                                  minutes=random.randint(0, 59))
            rows.append(ev(t, "connection_attempt", "network", "success", p,
                           host, "10.0.99.5", "United States", "Seattle",
                           net=random.randint(64, 1500), dst_ip=internal_ip(),
                           dst_port=random.choice([22, 445, 3389, 1433]),
                           process="nessus.exe", session=new_id()))

# ---------------------------------------------------------------------------
# DECOY NEAR-MISSES  (force the agent to discriminate, not pattern-match)
# ---------------------------------------------------------------------------
def add_decoys(profiles, rows):
    # Decoy A: legit impossible-travel-LOOKING event (corporate VPN egress).
    a = next(p for p in profiles if p["name"] != ATTACKER and p["role"] == "engineer")
    day = 2
    sid = new_id()
    base = START + timedelta(days=day, hours=14)
    rows.append(ev(base, "logon", "authentication", "success", a, a["host"],
                   home_ip(a["ip_prefix"]), a["country"], a["city"], session=sid))
    # appears from Berlin 10 min later -- but it's the company VPN, and there is
    # NO follow-on lateral movement or exfil. Innocent.
    rows.append(ev(base + timedelta(minutes=10), "logon", "authentication",
                   "success", a, a["host"], "91.13.20.5", "Germany", "Berlin",
                   session=sid))

    # Decoy B: a user who moves a big file legitimately (to a backup share).
    b = next(p for p in profiles if p["name"] not in (ATTACKER, a["name"]))
    t = START + timedelta(days=4, hours=11, minutes=20)
    rows.append(ev(t, "network_flow", "network", "success", b, b["host"],
                   home_ip(b["ip_prefix"]), b["country"], b["city"],
                   net=1_800_000_000, dst_ip="10.0.60.20", dst_port=443,
                   process="explorer.exe", session=new_id()))
    return [a["name"], b["name"]]

# ---------------------------------------------------------------------------
# THE ATTACK  (6-day dwell, multi-hop, real external exfil destination)
# ---------------------------------------------------------------------------
def add_attack(profiles, rows):
    mark = next(p for p in profiles if p["name"] == ATTACKER)
    truth = []

    def attack_ev(*args, **kwargs):
        stage = kwargs.pop("_stage", "")
        e = ev(*args, **kwargs)
        truth.append({"event.id": e["event.id"], "@timestamp": e["@timestamp"],
                      "stage": stage})
        return e

    seattle = home_ip("73.181")
    london = "81.149.30.7"

    # --- Day 0 (Mon): INITIAL ACCESS via phished creds ---------------------
    # A burst of failures (password spray fallout) then a success from an
    # unfamiliar host. Looks minor in isolation.
    d0 = START + timedelta(days=0, hours=23, minutes=12)
    for i in range(3):
        rows.append(attack_ev(d0 + timedelta(seconds=i*7), "logon",
                    "authentication", "failure", mark, "ws-0042", london,
                    "United Kingdom", "London", _stage="initial_access"))
    rows.append(attack_ev(d0 + timedelta(seconds=30), "logon", "authentication",
                "success", mark, "ws-0042", london, "United Kingdom", "London",
                _stage="initial_access"))

    # --- Day 1 (Tue) 02:14: off-hours access + IMPOSSIBLE TRAVEL -----------
    d1 = START + timedelta(days=1)
    rows.append(attack_ev(d1.replace(hour=2, minute=14, second=7), "logon",
                "authentication", "success", mark, "ws-0042", seattle,
                "United States", "Seattle", _stage="valid_accounts"))
    rows.append(attack_ev(d1.replace(hour=2, minute=34, second=51), "logon",
                "authentication", "success", mark, "ws-0042", london,
                "United Kingdom", "London", _stage="impossible_travel"))

    # --- Days 2-4: LOW & SLOW recon, off-hours, small footprint ------------
    for d in (2, 3, 4):
        day = START + timedelta(days=d)
        rows.append(attack_ev(day.replace(hour=3, minute=random.randint(5, 50)),
                    "logon", "authentication", "success", mark, "app-prod-03",
                    london, "United Kingdom", "London", _stage="lateral_recon"))
        rows.append(attack_ev(day.replace(hour=3, minute=random.randint(51, 59)),
                    "process_started", "process", "success", mark, "app-prod-03",
                    internal_ip(), "United Kingdom", "London",
                    process="powershell.exe", parent="services.exe",
                    cmdline="powershell -nop -w hidden -enc SQBFAFgA...",
                    _stage="lateral_recon"))

    # --- Day 6 (weekend night): MULTI-HOP to DB then EXFIL -----------------
    d6 = START + timedelta(days=6)  # Sunday
    rows.append(attack_ev(d6.replace(hour=2, minute=33), "logon",
                "authentication", "success", mark, "app-prod-03", london,
                "United Kingdom", "London", _stage="lateral_movement"))
    rows.append(attack_ev(d6.replace(hour=2, minute=41, second=30), "logon",
                "authentication", "success", mark, "db-prod-02", london,
                "United Kingdom", "London", _stage="lateral_movement"))
    rows.append(attack_ev(d6.replace(hour=2, minute=44, second=2),
                "process_started", "process", "success", mark, "db-prod-02",
                internal_ip(), "United Kingdom", "London", process="sqlcmd.exe",
                parent="powershell.exe",
                cmdline="sqlcmd -Q \"SELECT * FROM customers\" -o dump.csv",
                _stage="collection"))
    rows.append(attack_ev(d6.replace(hour=2, minute=47, second=12),
                "network_flow", "network", "success", mark, "db-prod-02",
                london, "United Kingdom", "London", net=EXFIL_BYTES,
                dst_ip=EXTERNAL_C2_IP, dst_port=443, process="powershell.exe",
                _stage="exfiltration"))

    return truth

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=DEFAULT_EVENTS)
    ap.add_argument("--out", default="logs.ndjson")
    ap.add_argument("--truth", default="ground_truth.json")
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    random.seed(args.seed if not args.clean else args.seed + 1)
    profiles = build_profiles()
    rows = []

    # Fill with coherent sessions until we hit the target event count.
    while len(rows) < args.events:
        prof = random.choice(profiles)
        day = random.randint(0, DAYS - 1)
        make_session(prof, day, rows)

    add_backups(rows)
    add_scans(rows)
    decoys = [] if args.clean else add_decoys(profiles, rows)
    truth = [] if args.clean else add_attack(profiles, rows)

    rows.sort(key=lambda r: r["@timestamp"])
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    if not args.clean:
        with open(args.truth, "w") as f:
            json.dump({
                "attacker": ATTACKER,
                "dwell_days": 6,
                "exfil_bytes": EXFIL_BYTES,
                "exfil_destination": {"ip": EXTERNAL_C2_IP,
                                      "country": EXFIL_DEST_COUNTRY},
                "lateral_path": ["ws-0042", "app-prod-03", "db-prod-02"],
                "decoy_users": decoys,
                "mitre": ["T1078 Valid Accounts", "T1021 Lateral Movement",
                          "T1059.001 PowerShell", "T1041 Exfil over C2"],
                "attack_events": truth,
            }, f, indent=2)

    # ---- verification report ----
    offhours = sum(1 for r in rows if r["event.category"] == "authentication"
                   and 0 <= int(r["@timestamp"][11:13]) <= 4)
    big = sum(1 for r in rows if r["network.bytes"] > 1_000_000_000)
    mark_total = sum(1 for r in rows if r["user.name"] == ATTACKER)
    mark_foreign = sum(1 for r in rows if r["user.name"] == ATTACKER
                       and r["source.geo.country_name"] != "United States")
    print(f"  wrote {len(rows):,} events -> {args.out}")
    print(f"  mode: {'CLEAN (no attack)' if args.clean else 'ATTACK present'}")
    print("  --- baseline + camouflage check ---")
    print(f"  off-hours (00-04) auth events : {offhours:,}  (attack hides here)")
    print(f"  transfers > 1 GB              : {big:,}  (exfil hides among backups)")
    if not args.clean:
        print(f"  mark.chen total events        : {mark_total:,}  (looks normal)")
        print(f"  mark.chen non-US events       : {mark_foreign}  (the needle)")
        print(f"  decoy near-miss users         : {decoys}")
        print(f"  attack events labelled        : {len(truth)} -> {args.truth}")


if __name__ == "__main__":
    main()

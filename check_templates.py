#!/usr/bin/env python3
"""
BLOODHOUND — check_templates.py
Closes Day-3 step 3: run EVERY template against the LIVE cluster and confirm it
returns without error. This is the only honest proof a template is "validated" —
offline logic passing is NOT the same as the live engine working.

Run AFTER `docker compose up -d` and `py -m ingest`:
    py -m check_templates

Output:
    OK   = ran with no error  (the plan's bar for step 3)
    FAIL = raised an error     (template/EQL/mapping problem — must fix)
    !    = ran fine but returned 0 where the attack SHOULD make it >0
           (logic worth a second look, not a hard failure)
"""
from queries import execute, TEMPLATES

# A valid param set for each template + whether the seeded attack should make
# it return at least one hit.
CHECKS = {
    "auth_offhours":           ({"max_hour": 4}, True),
    "auth_offhours_user":      ({"user": "mark.chen", "max_hour": 4}, True),
    "logons_for_user":         ({"user": "mark.chen"}, True),
    "logons_to_host":          ({"host": "db-prod-02"}, True),
    "failures_for_user":       ({"user": "mark.chen"}, True),
    "failed_then_success":     ({"maxspan": "10m"}, False),
    "impossible_travel":       ({"maxspan": "1h"}, True),
    "lateral_movement":        ({"maxspan": "2h"}, True),
    "large_outbound_external": ({"min_bytes": 1_000_000_000}, True),
    "transfers_from_host":     ({"host": "db-prod-02", "min_bytes": 1_000_000_000}, True),
    "external_egress":         ({}, True),
    "encoded_powershell":      ({}, True),
    "unusual_parent":          ({"proc": "powershell.exe", "expected_parent": "explorer.exe"}, True),
    "process_on_host":         ({"host": "db-prod-02"}, True),
}

def main():
    # safety: make sure every template has a check defined
    missing = set(TEMPLATES) - set(CHECKS)
    if missing:
        print(f"WARNING: no check defined for: {sorted(missing)}\n")

    passed = failed = warned = 0
    print(f"checking {len(CHECKS)} templates against the live cluster:\n")
    for tid, (params, expect_hits) in CHECKS.items():
        try:
            r = execute(tid, params)
            n = r["count"]
            flag = "OK  "
            note = ""
            if expect_hits and n == 0:
                flag, note = "OK !", "  <- expected >0 (attack should hit this)"
                warned += 1
            passed += 1
            print(f"  [{flag}] {tid:26} {n:>5} hits{note}")
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {tid:26} {type(e).__name__}: {e}")

    print(f"\n  {passed} ran, {failed} failed, {warned} returned 0 unexpectedly")
    if failed == 0 and warned == 0:
        print("  RESULT: Day-3 step 3 complete — every template valid AND finds the attack.")
    elif failed == 0:
        print("  RESULT: all templates run (step 3 met). Review the ! lines for logic.")
    else:
        print("  RESULT: fix the FAIL templates before calling step 3 done.")

if __name__ == "__main__":
    main()

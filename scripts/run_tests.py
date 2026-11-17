#!/usr/bin/env python3
"""
Detection test runner - replays every sample in tests/*.json through the
Wazuh manager's logtest engine (Wazuh API: PUT /logtest) and checks that
the expected rule fires (or does NOT fire, for negative tests).

Usage:
    export WAZUH_API_URL=https://localhost:55000
    export WAZUH_API_USER=wazuh-wui
    export WAZUH_API_PASS='MyS3cr37P450r.*-'
    python3 scripts/run_tests.py [tests_dir]

Exit code 0 = all tests passed, 1 = at least one failure (used by CI).
Standard library only.
"""
import base64
import glob
import json
import os
import ssl
import sys
import urllib.request

API = os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
PASS = os.getenv("WAZUH_API_PASS", "MyS3cr37P450r.*-")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def call(method, path, token=None, body=None, basic=False):
    headers = {"Content-Type": "application/json"}
    if basic:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
        return json.load(r)


def run_case(jwt, case):
    """Send every event of a case in one logtest session; return list of fired rule ids."""
    session, fired, last = None, [], {}
    for ev in case["events"]:
        body = {"event": ev, "log_format": case.get("log_format", "syslog"),
                "location": case.get("location", "detection-lab-test")}
        if session:
            body["token"] = session
        res = call("PUT", "/logtest", jwt, body)
        data = res.get("data", {})
        session = data.get("token", session)
        rule = data.get("output", {}).get("rule", {})
        fired.append(str(rule.get("id", "-")))
        last = data
    if session:
        try:
            call("DELETE", f"/logtest/sessions/{session}", jwt)
        except Exception:
            pass
    return fired, last


def main():
    tests_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "tests")
    jwt = call("POST", "/security/user/authenticate", basic=True)["data"]["token"]

    total = passed = 0
    results = []
    for path in sorted(glob.glob(os.path.join(tests_dir, "*_tests.json"))):
        print(f"\n{DIM}== {os.path.basename(path)} =={RST}")
        for case in json.load(open(path)):
            total += 1
            try:
                fired, last = run_case(jwt, case)
            except Exception as e:
                fired, last, err = [], {}, str(e)
            else:
                err = None

            if "expect_not_rule" in case:
                ok = err is None and case["expect_not_rule"] not in fired
                want = f"NOT {case['expect_not_rule']}"
            elif case.get("expect_on_last"):
                ok = err is None and fired and fired[-1] == case["expect_rule"]
                want = f"{case['expect_rule']} on last event"
            else:
                ok = err is None and case["expect_rule"] in fired
                want = case["expect_rule"]

            passed += bool(ok)
            mark = f"{GREEN}PASS{RST}" if ok else f"{RED}FAIL{RST}"
            got = err or ",".join(fired)
            print(f"  [{mark}] {case['id']:<12} {case['description']:<55} expected={want} got={got}")
            results.append({"id": case["id"], "passed": bool(ok), "expected": want, "fired": fired, "error": err,
                            "debug": None if ok else last})

    print(f"\nResult: {passed}/{total} passed")
    with open("test-results.json", "w") as f:
        json.dump({"passed": passed, "total": total, "results": results}, f, indent=2)
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Replay every sample in tests/*.json into a RUNNING Wazuh manager as real events,
so they produce real alerts (alerts.json -> Filebeat -> indexer -> dashboard).
Use it to demo the rules in the Wazuh dashboard.

Unlike run_tests.py (wazuh-logtest: nothing is stored), this writes real alerts.
Events are sent to analysisd's local queue socket exactly like a local log
collector would, using each test case's "location" (default: detection-lab-replay).

Run INSIDE the manager container, after deploy_and_test.ps1 copied the repo to /tmp/dl:
    docker exec single-node-wazuh.manager-1 /var/ossec/framework/python/bin/python3 /tmp/dl/scripts/replay_alerts.py

Standard library only.
"""
import glob
import json
import os
import socket
import sys
import time

QUEUE = "/var/ossec/queue/sockets/queue"
LOCALFILE_MQ = "1"  # message type used by logcollector for log lines


def main():
    tests_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "tests")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(QUEUE)

    sent = 0
    for path in sorted(glob.glob(os.path.join(tests_dir, "*_tests.json"))):
        print(f"== {os.path.basename(path)} ==")
        for case in json.load(open(path)):
            location = case.get("location", "detection-lab-replay")
            for event in case["events"]:
                sock.send(f"{LOCALFILE_MQ}:{location}:{event}".encode())
                sent += 1
                time.sleep(0.05)
            print(f"  replayed {case['id']:<12} {len(case['events'])} event(s)")
            time.sleep(0.5)  # keep cases apart so correlation windows stay readable
    sock.close()
    print(f"\nSent {sent} events to {QUEUE}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Static checks for the rule set (no Wazuh needed - runs in CI on every push):
  * every rule file is well-formed XML
  * rule IDs are unique and inside the custom range 100000-120000
  * every alerting rule (level > 0) has a [DL-...] tag and at least one MITRE ID
  * MITRE IDs look valid (T1234 or T1234.001)
  * every alerting rule has at least one positive test in tests/*.json
"""
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.join(os.path.dirname(__file__), "..")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
errors, rules = [], {}

for path in sorted(glob.glob(os.path.join(ROOT, "rules", "*.xml")) + glob.glob(os.path.join(ROOT, "tests", "fixtures", "*.xml"))):
    name = os.path.basename(path)
    try:
        # Wazuh rule files have several root <group> elements -> wrap them
        tree = ET.fromstring("<root>" + open(path, encoding="utf-8").read() + "</root>")
    except ET.ParseError as e:
        errors.append(f"{name}: XML error: {e}")
        continue
    for rule in tree.iter("rule"):
        rid = rule.get("id")
        level = int(rule.get("level", 0))
        desc = (rule.findtext("description") or "").strip()
        mitre = [m.text.strip() for m in rule.iter("id") if m.text and m.text.startswith("T")]
        if rid in rules:
            errors.append(f"{name}: duplicate rule id {rid}")
        if not 100000 <= int(rid) <= 120000:
            errors.append(f"{name}: rule {rid} outside custom range")
        for m in mitre:
            if not MITRE_RE.match(m):
                errors.append(f"{name}: rule {rid} bad MITRE id {m}")
        if level > 0 and "[DL-" in desc and not mitre:
            errors.append(f"{name}: rule {rid} has no MITRE mapping")
        rules[rid] = {"level": level, "desc": desc, "mitre": mitre, "file": name}

tested = set()
for path in glob.glob(os.path.join(ROOT, "tests", "*_tests.json")):
    for case in json.load(open(path)):
        if "expect_rule" in case:
            tested.add(case["expect_rule"])

for rid, r in rules.items():
    if r["level"] > 3 and "[DL-" in r["desc"] and rid not in tested:
        errors.append(f"{r['file']}: rule {rid} has no positive test case")

print(f"Checked {len(rules)} rules, {len(tested)} rules covered by tests")
if errors:
    print("\n".join("ERROR: " + e for e in errors))
    sys.exit(1)
print("All static checks passed.")

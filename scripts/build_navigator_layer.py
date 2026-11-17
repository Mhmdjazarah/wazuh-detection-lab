#!/usr/bin/env python3
"""
Generate a MITRE ATT&CK Navigator layer from the MITRE IDs in rules/*.xml.
Open https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer
-> Upload from local -> mitre/detection-lab-layer.json
"""
import glob
import json
import os
import re
import xml.etree.ElementTree as ET

ROOT = os.path.join(os.path.dirname(__file__), "..")
techniques = {}

for path in sorted(glob.glob(os.path.join(ROOT, "rules", "*.xml"))):
    tree = ET.fromstring("<root>" + open(path, encoding="utf-8").read() + "</root>")
    for rule in tree.iter("rule"):
        desc = rule.findtext("description") or ""
        tag = re.search(r"\[(DL-[A-Z]+-\d+[a-z]?)\]", desc)
        if not tag or int(rule.get("level", 0)) == 0:
            continue
        for m in rule.iter("id"):
            if m.text and m.text.startswith("T"):
                t = techniques.setdefault(m.text.strip(), {"rules": [], "max": 0})
                t["rules"].append(f"{rule.get('id')} {tag.group(1)}")
                t["max"] = max(t["max"], int(rule.get("level")))

layer = {
    "name": "Wazuh Detection Engineering Lab",
    "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Techniques covered by custom Wazuh rules (score = highest rule level)",
    "gradient": {"colors": ["#fff3b0", "#f4a259", "#bc4b51"], "minValue": 0, "maxValue": 15},
    "techniques": [
        {"techniqueID": tid, "score": t["max"], "enabled": True,
         "comment": "; ".join(t["rules"])}
        for tid, t in sorted(techniques.items())
    ],
    "legendItems": [{"label": "Detected by custom rule", "color": "#f4a259"}],
}
out = os.path.join(ROOT, "mitre", "detection-lab-layer.json")
json.dump(layer, open(out, "w"), indent=2)
print(f"Wrote {out} with {len(techniques)} techniques")

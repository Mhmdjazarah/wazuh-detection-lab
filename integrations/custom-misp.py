#!/var/ossec/framework/python/bin/python3
"""
Wazuh -> MISP enrichment integration (Detection Engineering Lab)

Wazuh integratord calls this script for every alert that matches the
<integration> block in ossec.conf:

    custom-misp.py <alert_file> <api_key> <hook_url>

It extracts IOCs from the alert (IPs, domains, URLs, file hashes), looks
each one up in MISP via /attributes/restSearch, and writes the result
back into Wazuh's analysis queue as a JSON event with "integration": "misp".
Rules 100600-100603 then turn matches into alerts.

Only the Python standard library is used.
"""
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.request
from socket import AF_UNIX, SOCK_DGRAM, socket
from urllib.parse import urlparse

WAZUH_QUEUE = "/var/ossec/queue/sockets/queue"
LOG_FILE = "/var/ossec/logs/integrations.log"
VERIFY_TLS = os.getenv("MISP_VERIFY_TLS", "false").lower() == "true"
TIMEOUT = 10

HASH_RE = re.compile(r"(?i)(MD5|SHA1|SHA256)=([0-9a-f]{32,64})")


def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} custom-misp: {msg}\n")
    except OSError:
        pass


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved
                    or ip.is_multicast or ip.is_link_local)
    except ValueError:
        return False


def get(d, path):
    for key in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def extract_iocs(alert):
    """Return a list of (value, misp_type_hint) tuples found in the alert."""
    iocs = []
    data = alert.get("data", {})

    for field in ("srcip", "dstip"):
        v = data.get(field)
        if v and is_public_ip(v):
            iocs.append((v, "ip"))

    win = data.get("win", {}).get("eventdata", {})
    for field in ("destinationIp", "sourceIp"):
        v = win.get(field)
        if v and is_public_ip(v):
            iocs.append((v, "ip"))

    domain = win.get("queryName") or win.get("destinationHostname")
    if domain:
        iocs.append((domain.lower(), "domain"))

    url = data.get("url")
    if url and url.startswith("http"):
        host = urlparse(url).hostname
        if host:
            iocs.append((host.lower(), "domain"))

    hashes = win.get("hashes") or get(alert, "syscheck.sha256_after")
    if hashes:
        for _, h in HASH_RE.findall(hashes) or [("SHA256", hashes)]:
            if re.fullmatch(r"[0-9a-fA-F]{32,64}", h):
                iocs.append((h.lower(), "hash"))

    # de-duplicate, keep order
    seen, out = set(), []
    for v, t in iocs:
        if v not in seen:
            seen.add(v)
            out.append((v, t))
    return out


def misp_search(base_url, api_key, value):
    ctx = ssl.create_default_context()
    if not VERIFY_TLS:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps({"value": value, "returnFormat": "json",
                       "limit": 1, "includeEventTags": False}).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/attributes/restSearch", data=body, method="POST",
        headers={"Authorization": api_key, "Accept": "application/json",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
        attrs = json.load(r).get("response", {}).get("Attribute", [])
    return attrs[0] if attrs else None


def send_event(payload, agent):
    if agent and agent.get("id") != "000":
        location = f"[{agent['id']}] ({agent.get('name')}) {agent.get('ip', 'any')}->misp"
    else:
        location = "misp"
    msg = f"1:{location}:{json.dumps(payload)}"
    sock = socket(AF_UNIX, SOCK_DGRAM)
    try:
        sock.connect(WAZUH_QUEUE)
        sock.send(msg.encode())
    finally:
        sock.close()


def main():
    if len(sys.argv) < 4:
        log("usage: custom-misp.py <alert_file> <api_key> <misp_url>")
        sys.exit(1)
    alert_file, api_key, misp_url = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(alert_file) as f:
        alert = json.load(f)

    # never enrich our own MISP events (avoid loops)
    if "misp" in alert.get("rule", {}).get("groups", []):
        return

    agent = alert.get("agent", {})
    for value, hint in extract_iocs(alert):
        base = {"integration": "misp",
                "misp": {"value": value, "ioc_kind": hint},
                "source": {"alert_id": alert.get("id"),
                           "rule_id": alert.get("rule", {}).get("id"),
                           "description": alert.get("rule", {}).get("description")}}
        try:
            attr = misp_search(misp_url, api_key, value)
        except Exception as e:  # network / auth / TLS problem
            base["misp"]["error"] = str(e)[:200]
            send_event(base, agent)
            log(f"error querying {value}: {e}")
            continue

        if attr:
            event = attr.get("Event", {})
            base["misp"].update({
                "matched": "true",
                "event_id": attr.get("event_id"),
                "event_info": event.get("info"),
                "category": attr.get("category"),
                "type": attr.get("type"),
                "to_ids": str(attr.get("to_ids", False)).lower(),
                "attribute_uuid": attr.get("uuid"),
            })
            send_event(base, agent)
            log(f"MATCH {value} -> MISP event {attr.get('event_id')}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"fatal: {exc}")
        sys.exit(1)

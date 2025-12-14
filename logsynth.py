#!/usr/bin/env python3
import json
import argparse
import hashlib
from datetime import datetime

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]

def iter_docs(path: str):
    """
    Supports:
    1) Elasticsearch _search JSON response
    2) NDJSON / JSON-lines
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()

    if not raw:
        return

    # Elasticsearch response
    if raw.startswith("{"):
        data = json.loads(raw)
        hits = data.get("hits", {}).get("hits", [])
        for h in hits:
            yield h
        return

    # NDJSON fallback
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue

# -------------------------------------------------
# Detection logic
# -------------------------------------------------

def detect_event(doc):
    """
    Detects attack based on endpoint / message evidence.
    Payload visibility NOT required.
    """
    src = doc.get("_source", {})
    msg = src.get("message", "").lower()

    # DVWA command execution
    if "/vulnerabilities/exec" in msg:
        return {
            "attack": "Command Execution",
            "technique": "T1059",
            "tactic": "Execution",
            "confidence": "high",
            "app": "DVWA"
        }

    # Juice Shop SQL injection (login)
    if "/rest/user/login" in msg:
        return {
            "attack": "SQL Injection (Auth Bypass)",
            "technique": "T1190",
            "tactic": "Initial Access",
            "confidence": "medium",
            "app": "OWASP Juice Shop"
        }

    return None

# -------------------------------------------------
# Main
# -------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="LogSynth – Web logs to ATT&CK events")
    parser.add_argument("-i", "--input", required=True, help="Input JSON (Elastic search export)")
    parser.add_argument("-o", "--output", required=True, help="Output NDJSON")
    args = parser.parse_args()

    out = open(args.output, "w", encoding="utf-8")

    total = 0
    matched = 0

    for doc in iter_docs(args.input):
        total += 1
        event = detect_event(doc)
        if not event:
            continue

        matched += 1
        src = doc.get("_source", {})

        ts = src.get("@timestamp", datetime.utcnow().isoformat() + "Z")
        message = src.get("message", "")

        out_doc = {
            "@timestamp": ts,
            "event": {
                "category": "attack",
                "type": "web",
                "action": event["attack"],
                "confidence": event["confidence"]
            },
            "attack": {
                "tactic": event["tactic"],
                "technique": event["technique"],
                "framework": "MITRE ATT&CK"
            },
            "service": {
                "name": event["app"]
            },
            "log": {
                "original": message
            },
            "observer": {
                "name": "LogSynth"
            },
            "event_id": sha1(message + ts)
        }

        out.write(json.dumps(out_doc) + "\n")

    out.close()

    print(f"Processed: {total} logs")
    print(f"Matched:   {matched} attack events")
    print(f"Output ->  {args.output}")

# -------------------------------------------------
# Entry
# -------------------------------------------------

if __name__ == "__main__":
    main()

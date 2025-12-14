# LogSynth – Web Attack Log Enrichment Tool

## Overview

**LogSynth** is a lightweight security analysis tool that converts raw web server logs collected from vulnerable web applications (e.g., **OWASP Juice Shop** and **DVWA**) into **MITRE ATT&CK–tagged security events**.

The tool is designed for **CTF practice, blue-team learning, and SOC-style analysis**, enabling students to transform application logs into structured attack events suitable for ingestion into **ELK / HELK** environments.

LogSynth operates as an **offline enrichment pipeline** that bridges the gap between raw web logs and higher-level security intelligence.

---

## Features

- Converts Elasticsearch-exported web logs into **NDJSON security events**
- Tags events with **MITRE ATT&CK tactics and techniques**
- Supports:
  - SQL Injection (OWASP Juice Shop)
  - Command Execution (DVWA)
- Produces output compatible with:
  - Elastic Stack
  - HELK
  - SIEM pipelines
- Simple CLI interface
- No payload dependency (works even if payload is not visible in logs)

---

## Architecture

```
[ Web App ]
   │
   ▼
[ Web Server Logs ]
   │
   ▼
[ Filebeat ]
   │
   ▼
[ Elasticsearch ]
   │
   ▼ (Export JSON)
[ LogSynth ]
   │
   ▼
[ ATT&CK-tagged NDJSON Events ]
```

---

## Supported Use Cases

| Application | Attack Type | Detection Method |
|------------|------------|------------------|
| OWASP Juice Shop | SQL Injection (Auth Bypass) | POST `/rest/user/login` |
| DVWA | Command Injection | `/vulnerabilities/exec/` |

---

## Requirements

- Python **3.8+**
- Elasticsearch (for log collection & export)
- Filebeat (for log ingestion)
- Linux environment (tested on Ubuntu 24.04)

---

## Installation

```bash
git clone https://github.com/your-username/logsynth.git
cd logsynth
```

No external Python libraries are required.

---

## Usage

### Export Logs from Elasticsearch

**Juice Shop SQLi filter**
```
message: "rest/user/login"
```

**DVWA Command Injection filter**
```
message: "exec"
```

Export results as JSON from Discover.

---

### Run LogSynth

```bash
python3 logsynth.py -i juice_login.json -o juice_events.ndjson
```

```bash
python3 logsynth.py -i dvwa_exec.json -o dvwa_events.ndjson
```

---

## Output Example

```json
{
  "@timestamp": "2025-12-10T07:23:46.399Z",
  "event": {
    "category": "attack",
    "type": "web",
    "action": "SQL Injection (Auth Bypass)"
  },
  "attack": {
    "tactic": "Initial Access",
    "technique": "T1190",
    "framework": "MITRE ATT&CK"
  },
  "service": {
    "name": "OWASP Juice Shop"
  },
  "observer": {
    "name": "LogSynth"
  }
}
```

---

## MITRE ATT&CK Mapping

| Attack | Tactic | Technique |
|------|-------|-----------|
| SQL Injection (Auth Bypass) | Initial Access | T1190 |
| Command Injection | Execution | T1059 |

---

## Project Structure

```
logsynth/
│
├── logsynth.py
├── README.md
├── examples/
│   ├── juice_login.json
│   ├── dvwa_exec.json
│
├── output/
│   ├── juice_events.ndjson
│   ├── dvwa_events.ndjson
│
└── LICENSE
```

---

## License

MIT License

---

## Author

Developed as part of **Final CTF Helper Tool**  
College of Computer Science & Engineering  
University of Jeddah

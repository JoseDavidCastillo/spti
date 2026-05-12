# Security Automation Toolkit

**Topic:** Automation for Security Tasks  
**Authors:** Jose Castillo and Sebastian Galvis  
**Environment used:** Kali Linux  
**Language:** Python 3

---

## 1. Project Overview

This repository contains a Python-based security automation toolkit developed for the **Automation** workshop. The objective of the project is to automate common reconnaissance, parsing, log-analysis, and reporting tasks using Python scripts and Kali Linux tools.

The project is organized as a multi-stage security pipeline:

1. **Concurrent port scanning** using threading and `asyncio`.
2. **Nmap XML parsing** to convert raw scan output into structured JSON.
3. **SSH enrichment** using `ssh-keyscan` for hosts with port `22` open.
4. **Authentication log analysis** to detect brute-force login attempts.
5. **Web access log analysis** to detect suspicious requests and traffic anomalies.
6. **Integrated reporting** through `recon.py`, producing `results.json`, `report.md`, and audit logs.

The scripts were designed to be configurable, reproducible, and easy to execute from the command line.

---

## 2. Repository Structure

```text
.
├── auth_analysis.py                 # Part 3: SSH authentication log analysis
├── log_analysis.py                  # Part 3: Web access log analysis and anomaly detection
├── parse_scan.py                    # Part 2: Nmap XML parser and optional SSH enrichment
├── recon.py                         # Part 4: Integrated reconnaissance and reporting tool
├── README.md                        # Project documentation
│
├── scanners/
│   ├── asyncio_scanner.py           # Part 1B: Async scanner performance comparison
│   ├── cli_scanner.py               # Part 1C-D: CLI concurrent port scanner with JSON output
│   └── scanner_mejorado.py          # Part 1A: ThreadPoolExecutor scanner comparison
│
├── outputs_proceso/
│   ├── hosts.json                   # Parsed Nmap host results
│   ├── results.json                 # Structured process output
│   ├── scan.xml                     # Nmap XML output
│   └── report.md                    # Generated security analysis report
│
├── sample_output(127.0.0.1)/
│   ├── audit_20260511_225543.log    # Audit log from an integrated execution
│   ├── results.json                 # JSON output from recon.py
│   └── report.md                    # Markdown report from recon.py
│
└── img/
    └── screenshots of execution evidence
```

> Note: The main CLI scanner for Part 1 is implemented as `scanners/cli_scanner.py`. If the submission requires a root-level `scanner.py`, this file can be copied or renamed to `scanner.py` without changing its logic.

---

## 3. Requirements

### 3.1 System Requirements

This project was tested in **Kali Linux**.

Required system tools:

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap openssh-client dnsutils whois curl
```

Required versions:

```bash
python3 --version
nmap --version
ssh-keyscan -h
```

Recommended Python version:

```text
Python 3.10+
```

### 3.2 Python Dependencies

The project uses only Python standard-library modules such as:

- `argparse`
- `asyncio`
- `socket`
- `subprocess`
- `xml.etree.ElementTree`
- `json`
- `re`
- `statistics`
- `logging`
- `datetime`
- `collections`
- `pathlib`

No external Python packages are required.

A valid pip setup command is:

```bash
python3 -m pip install --upgrade pip
```

---

## 4. How to Run Each Script

All commands should be executed from the project root directory.

---

## 4.1 Part 1 — Concurrent Port Scanner

### A. ThreadPoolExecutor comparison

The script `scanner_mejorado.py` compares different thread counts while scanning localhost ports `1-1024`.

```bash
python3 scanners/scanner_mejorado.py
```

Example output:

```text
workers=50: 0.19s
workers=200: 0.26s
workers=500: 0.24s
```

This script demonstrates how concurrency improves scanning performance for I/O-bound network tasks.

---

### B. Asyncio scanner comparison

The script `asyncio_scanner.py` tests the same scan using `asyncio` with different concurrency limits.

```bash
python3 scanners/asyncio_scanner.py
```

Example output:

```text
rate=50: 0.12s  ports=[]
rate=200: 0.12s ports=[]
rate=500: 0.14s ports=[]
```

This version uses an event loop and an `asyncio.Semaphore` to control the maximum number of concurrent connections.

---

### C. CLI scanner with JSON output

The script `cli_scanner.py` is the configurable command-line scanner.

Run a basic scan:

```bash
python3 scanners/cli_scanner.py 127.0.0.1 --ports 1-1024 --rate 200 --timeout 0.5
```

Save results to JSON:

```bash
python3 scanners/cli_scanner.py 127.0.0.1 --ports 1-1024 --rate 200 --timeout 0.5 --output results.json
```

Example JSON output:

```json
{
  "target": "127.0.0.1",
  "scan_time_seconds": 0.11,
  "timestamp": "2026-05-11T20:51:27.454822",
  "open_ports": []
}
```

The `--ports` argument supports both ranges and comma-separated lists:

```bash
python3 scanners/cli_scanner.py 127.0.0.1 --ports 22,80,443
python3 scanners/cli_scanner.py 127.0.0.1 --ports 1-1024
```

---

## 4.2 Part 2 — Nmap XML Parsing and SSH Enrichment

First, generate an Nmap XML scan file:

```bash
nmap -sV --open -oX scan.xml 192.168.182.128/24
```

Then parse the XML file:

```bash
python3 parse_scan.py --input scan.xml
```

Save parsed results to `hosts.json`:

```bash
python3 parse_scan.py --input scan.xml --output hosts.json
```

Run with SSH key enrichment:

```bash
python3 parse_scan.py --input scan.xml --output hosts.json --ssh
```

Example parsed output:

```json
[
  {
    "ip": "192.168.182.2",
    "hostname": "192.168.182.2",
    "open_ports": [
      {
        "port": 53,
        "service": "domain",
        "version": ""
      }
    ]
  }
]
```

The parser extracts:

- Host IP address
- Hostname, when available
- Open ports
- Service name
- Service version, when available
- SSH host key type, when `--ssh` is used and port `22` is open

---

## 4.3 Part 3 — Authentication Log Analysis

The script `auth_analysis.py` reads an SSH authentication log and identifies IP addresses with repeated failed login attempts.

```bash
python3 auth_analysis.py --input auth.log --threshold 10
```

Example output:

```text
[!] IPs con más de 10 intentos fallidos:

IP                     Intentos
--------------------------------
185.220.101.5               258
45.33.32.156                214
10.0.0.2                     12
```

This logic is useful for detecting brute-force behavior by grouping failed login attempts by source IP.

---

## 4.4 Part 3 — Web Access Log Analysis and Anomaly Detection

The script `log_analysis.py` analyzes an `access.log` file.

```bash
python3 log_analysis.py --input access.log
```

It reports:

- Top IPs by request volume
- HTTP status code distribution
- Suspicious requests matching common attack patterns
- Traffic anomalies using the 3-sigma rule

Detected attack patterns include:

- SQL injection
- Path traversal
- Cross-site scripting
- Command injection

Example output sections:

```text
=== TOP 10 IPs ===
10.0.0.1              1765 requests
66.249.66.1            625 requests
45.33.32.156           317 requests
185.220.101.5          291 requests
192.168.1.50           183 requests
```

```text
=== STATUS CODES ===
200: 3099
403: 33
500: 49
```

```text
=== ANOMALÍAS DE TRÁFICO (3-sigma) ===
[ANOMALY] 11/May/2026-03 — 950 requests (z=4.7σ, threshold=3.0σ)
```

---

## 4.5 Part 4 — Integrated Reconnaissance Tool

The script `recon.py` integrates the main tasks into a single command-line workflow.

Example run against localhost:

```bash
python3 recon.py \
  --target 127.0.0.1 \
  --ports 1-1024 \
  --rate 200 \
  --timeout 0.5 \
  --nmap \
  --auth auth.log \
  --access access.log \
  --output results.json \
  --report report.md
```

Example run against a lab subnet:

```bash
python3 recon.py \
  --target 192.168.182.128/24 \
  --ports 1-1024 \
  --rate 200 \
  --timeout 0.5 \
  --nmap \
  --ssh \
  --auth auth.log \
  --access access.log \
  --output results.json \
  --report report.md
```

`recon.py` can perform:

- Async port scan
- Optional Nmap service scan
- Optional SSH host key enrichment
- SSH brute-force detection from `auth.log`
- Web access log analysis from `access.log`
- 3-sigma anomaly detection
- JSON result generation
- Markdown report generation
- Timestamped audit logging

Generated files include:

```text
results.json
report.md
audit_YYYYMMDD_HHMMSS.log
```

---

## 5. Sample Outputs

The repository includes sample output folders with real execution artifacts.

### `sample_output(127.0.0.1)/`

Contains a complete run against localhost:

```text
sample_output(127.0.0.1)/
├── audit_20260511_225543.log
├── results.json
└── report.md
```

Observed result:

```json
{
  "port_scan": {
    "target": "127.0.0.1",
    "elapsed": 0.13,
    "open_ports": []
  }
}
```

The same execution also analyzed `auth.log` and `access.log`, detecting:

- 3 IPs with brute-force behavior
- 95 suspicious web requests
- 1 anomalous traffic spike

---

### `outputs_proceso/`

Contains evidence from the Nmap and parsing workflow:

```text
outputs_proceso/
├── hosts.json
├── results.json
├── scan.xml
└── report.md
```

The Nmap XML parsing process identified the following host:

```json
[
  {
    "ip": "192.168.182.2",
    "hostname": "192.168.182.2",
    "open_ports": [
      {
        "port": 53,
        "service": "domain",
        "version": ""
      }
    ]
  }
]
```

---

## 6. Design Decisions

### 6.1 Why use concurrency?

Port scanning is mostly I/O-bound. Most of the execution time is spent waiting for network responses, timeouts, or connection refusals. Because of this, concurrency significantly improves performance.

The project includes both approaches:

- `ThreadPoolExecutor`, which is simple and effective for I/O-bound tasks.
- `asyncio`, which is more lightweight and scales better for high-concurrency network operations.

The CLI scanner uses `asyncio` because it offers good performance while keeping resource usage lower than creating many OS threads.

---

### 6.2 Why use `argparse`?

`argparse` makes the scripts reusable and configurable. Instead of hardcoding IP addresses, port ranges, output paths, or thresholds, the user can provide them from the command line.

This makes the scripts easier to test and more suitable for different lab scenarios.

---

### 6.3 Why output JSON?

JSON is structured, easy to parse, and easy to reuse in later stages of a pipeline. The project separates machine-readable output from human-readable reporting:

- `results.json` is intended for automated processing.
- `report.md` is intended for review and delivery.

---

### 6.4 Why parse Nmap XML?

Human-readable Nmap output is useful for manual inspection, but XML is better for automation. The XML structure allows the script to reliably extract hosts, ports, states, services, and versions without fragile string parsing.

The implementation uses Python’s built-in `xml.etree.ElementTree`, as required by the workshop.

---

### 6.5 Why use audit logs?

Audit logs are important in security automation because they provide evidence of what the script executed, when it executed, and what results were produced.

In this project, `recon.py` creates timestamped audit logs that record major actions such as:

- Port scanning
- Nmap execution
- Authentication log analysis
- Access log analysis
- JSON output generation
- Markdown report generation

---

## 7. Answers to Workshop Questions

### Question 1 — False negatives at very high concurrency

At very high concurrency, for example `--rate 2000`, the scanner may produce false negatives. This can happen because the local machine, the target machine, or the network path may become overloaded.

Possible causes include:

- Too many simultaneous sockets opened by the scanner.
- Local ephemeral port exhaustion.
- File descriptor limits.
- Target-side rate limiting.
- Firewall rules dropping excessive probes.
- Network packet loss.
- Timeouts that are too aggressive.

Because of this, “the scanner did not detect the port as open” is not the same as saying “the port is definitely closed.” It only means the scanner did not receive a successful connection response within the configured conditions.

This also applies to tools like Nmap. Scan results must be interpreted as observations under specific timing, network, privilege, and configuration conditions, not as absolute truth.

---

### Question 2 — Value of service version detection

Service version detection is valuable because it gives attackers more precise information about the software exposed by a target.

For example, knowing that a server is running `Apache httpd 2.4.54` allows an attacker to search for vulnerabilities, misconfigurations, or exploit techniques associated with that exact version.

A server that returns no version string gives away less information. The port and service may still be discoverable, but the attacker must spend more time fingerprinting the system manually.

The security-relevant difference is information exposure. Version banners reduce uncertainty for attackers and make vulnerability matching easier.

---

### Question 3 — Limitations of a global 3-sigma baseline

The 3-sigma rule assumes the data is approximately normally distributed. Web traffic often does not behave this way because it has predictable daily cycles.

For example, a production web server may naturally have more traffic during business hours and much less traffic overnight. If one global baseline is used for the entire day, normal business-hour traffic may look anomalous, or unusual overnight activity may be hidden by the global average.

A better approach is to use time-aware baselines, such as:

- Separate baselines per hour of the day.
- Separate baselines per day of the week.
- Rolling windows based on recent historical traffic.
- Seasonal models that compare Monday 9:00 AM with previous Mondays at 9:00 AM.

This would reduce false positives because the detector would compare traffic against the expected pattern for that specific time period.

---

### Question 4 — Active vs passive reconnaissance

Active reconnaissance sends packets directly to the target. Examples include port scanning, service detection, and HTTP header collection. This gives fresh and specific results, but it can be detected by defenders through firewall logs, IDS alerts, or server logs.

Passive reconnaissance uses existing third-party information, such as data from Shodan. In that case, the attacker queries an external database instead of touching the target directly.

From an attacker’s perspective:

- Active reconnaissance is more current and customizable.
- Passive reconnaissance is quieter and usually safer operationally.

From a defender’s perspective:

- Active reconnaissance is easier to detect because the traffic reaches the monitored network.
- Passive reconnaissance is harder to detect because the target does not receive packets from the attacker.

Active reconnaissance is more appropriate when fresh validation is required and the tester has authorization. Passive reconnaissance is more appropriate for initial intelligence gathering or when avoiding direct interaction with the target is important.

---

## 8. Security and Ethical Use

This toolkit is intended only for educational use and authorized security testing.

Only run these scripts against:

- Localhost
- Lab environments
- Machines you own
- Networks where you have explicit permission

Automated scanning against unauthorized systems may be illegal and can negatively affect target availability.

---

## 9. Submission Checklist

The repository includes the required components for the workshop:

- [x] Concurrent scanner implementation
- [x] Threading performance comparison
- [x] Asyncio performance comparison
- [x] CLI scanner with configurable target, ports, rate, timeout, and JSON output
- [x] Nmap XML parser using `xml.etree.ElementTree`
- [x] SSH key enrichment using `ssh-keyscan`
- [x] Authentication log analysis
- [x] Web access log analysis
- [x] Suspicious request detection
- [x] 3-sigma anomaly detection
- [x] Integrated `recon.py` tool
- [x] `results.json` output
- [x] `report.md` output
- [x] Audit log evidence
- [x] Sample output folder
- [x] Execution screenshots in `img/`
- [x] README with setup instructions and script explanations

---

## 10. Authors

- Jose Castillo
- Sebastian Galvis


import re
import argparse
import statistics
from collections import Counter, defaultdict
from pathlib import Path

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+)'
)

ATTACK_PATTERNS = re.compile(
    r"(union.*select|insert.*into|drop\s+table"
    r"|\.\.\/|\.\.\\\\)"
    r"|<script"
    r"|cmd=|exec=|shell=",
    re.IGNORECASE,
)

def analyze_access_log(path):
    ip_counts = Counter()
    status_counts = Counter()
    suspicious = []

    for line in Path(path).open():
        m = LOG_PATTERN.match(line)
        if not m:
            continue
        ip = m.group("ip")
        status = m.group("status")
        req_path = m.group("path")

        ip_counts[ip] += 1
        status_counts[status] += 1

        if ATTACK_PATTERNS.search(req_path):
            suspicious.append({
                "ip": ip,
                "path": req_path,
                "status": status
            })

    return {
        "top_ips": ip_counts.most_common(10),
        "status_distribution": dict(status_counts),
        "suspicious_requests": suspicious
    }

def detect_traffic_spikes(log_path):
    hourly = Counter()
    for line in Path(log_path).open():
        if m := re.search(r'\[(\d{2}/\w+/\d{4}):(\d{2}):', line):
            hourly[f"{m.group(1)}-{m.group(2)}"] += 1

    counts = list(hourly.values())
    if len(counts) < 2:
        return []

    mean = statistics.mean(counts)
    stdev = statistics.stdev(counts)
    threshold = mean + 3 * stdev

    anomalies = []
    for hour, count in hourly.items():
        if count > threshold:
            z = (count - mean) / stdev
            anomalies.append(f"[ANOMALY] {hour} — {count} requests (z={z:.1f}σ, threshold=3.0σ)")
    return anomalies

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Análisis de access.log")
    parser.add_argument("--input", default="access.log", help="Archivo access.log")
    args = parser.parse_args()

    print(f"[*] Analizando {args.input}...\n")
    results = analyze_access_log(args.input)

    print("=== TOP 10 IPs ===")
    for ip, count in results["top_ips"]:
        print(f"  {ip:<20} {count} requests")

    print("\n=== STATUS CODES ===")
    for status, count in sorted(results["status_distribution"].items()):
        print(f"  {status}: {count}")

    print(f"\n=== REQUESTS SOSPECHOSAS ({len(results['suspicious_requests'])}) ===")
    for r in results["suspicious_requests"]:
        print(f"  [{r['status']}] {r['ip']} → {r['path']}")

    print("\n=== ANOMALÍAS DE TRÁFICO (3-sigma) ===")
    anomalies = detect_traffic_spikes(args.input)
    if anomalies:
        for a in anomalies:
            print(f"  {a}")
    else:
        print("  Sin anomalías detectadas.")

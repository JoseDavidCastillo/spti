import argparse
import asyncio
import socket
import subprocess
import xml.etree.ElementTree as ET
import json
import datetime
import logging
import time
import re
from collections import defaultdict, Counter
from pathlib import Path

# ─────────────────────────────────────────
# LOGGING / AUDIT
# ─────────────────────────────────────────
logging.basicConfig(
    filename=f"audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def log(msg):
    print(msg)
    logging.info(msg)

# ─────────────────────────────────────────
# PORT SCANNER (asyncio)
# ─────────────────────────────────────────
async def scan_port(host, port, timeout):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_host(host, ports, max_concurrent, timeout):
    sem = asyncio.Semaphore(max_concurrent)
    async def limited(p):
        async with sem:
            await asyncio.sleep(0)
            return await scan_port(host, p, timeout)
    results = await asyncio.gather(*[limited(p) for p in ports])
    return sorted(p for p in results if p)

def parse_ports(s):
    ports = []
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return ports

def run_port_scan(target, ports, rate, timeout):
    log(f"[*] Escaneando {target} — {len(ports)} puertos, rate={rate}, timeout={timeout}s")
    start = time.perf_counter()
    open_ports = asyncio.run(scan_host(target, ports, rate, timeout))
    elapsed = round(time.perf_counter() - start, 2)
    log(f"[+] Puertos abiertos en {target}: {open_ports} ({elapsed}s)")
    return open_ports, elapsed

# ─────────────────────────────────────────
# NMAP + XML PARSER
# ─────────────────────────────────────────
def run_nmap(target, xml_out="scan.xml"):
    log(f"[*] Corriendo nmap -sV en {target}...")
    try:
        subprocess.run(
            ["nmap", "-sV", "--open", "-oX", xml_out, target],
            check=True, capture_output=True, text=True
        )
        log(f"[+] nmap completado → {xml_out}")
        return xml_out
    except subprocess.CalledProcessError as e:
        log(f"[!] nmap falló: {e}")
        return None

def parse_nmap_xml(xml_path):
    root = ET.parse(xml_path).getroot()
    hosts = []
    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        hostname_el = host.find(".//hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else ""
        ports = []
        for p in host.findall(".//port"):
            if p.find("state").get("state") == "open":
                svc = p.find("service")
                ports.append({
                    "port": int(p.get("portid")),
                    "service": svc.get("name", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else ""
                })
        if ports:
            hosts.append({
                "ip": addr,
                "hostname": hostname,
                "open_ports": ports
            })
    return hosts

# ─────────────────────────────────────────
# SSH KEYSCAN
# ─────────────────────────────────────────
def get_ssh_key_type(ip):
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", "3", ip],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
        return "no-key-found"
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception as e:
        return f"error: {str(e)}"

# ─────────────────────────────────────────
# AUTH LOG ANALYSIS
# ─────────────────────────────────────────
AUTH_FAIL = re.compile(r"Failed password for \S+ from (\d+\.\d+\.\d+\.\d+)")

def detect_brute_force(log_path, threshold=10):
    attempts = defaultdict(int)
    for line in Path(log_path).open():
        if m := AUTH_FAIL.search(line):
            attempts[m.group(1)] += 1
    suspects = [(ip, c) for ip, c in attempts.items() if c >= threshold]
    return sorted(suspects, key=lambda x: -x[1])

# ─────────────────────────────────────────
# WEB LOG ANALYSIS
# ─────────────────────────────────────────
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
            suspicious.append({"ip": ip, "path": req_path, "status": status})
    return {
        "top_ips": ip_counts.most_common(10),
        "status_distribution": dict(status_counts),
        "suspicious_requests": suspicious
    }

def detect_traffic_spikes(log_path):
    import statistics
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

# ─────────────────────────────────────────
# REPORTE MARKDOWN
# ─────────────────────────────────────────
def generate_report(data, output="report.md"):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("# Security Recon Report")
    lines.append(f"\nGenerado: {now}\n")

    # --- Scan de puertos ---
    if "port_scan" in data:
        ps = data["port_scan"]
        lines.append("---\n## 1. Port Scan\n")
        lines.append(f"- **Target:** {ps['target']}")
        lines.append(f"- **Tiempo:** {ps['elapsed']}s")
        lines.append(f"- **Puertos abiertos:** {ps['open_ports']}\n")

    # --- nmap / hosts ---
    if "hosts" in data and data["hosts"]:
        lines.append("---\n## 2. Hosts Descubiertos (nmap)\n")
        for h in data["hosts"]:
            lines.append(f"### {h['ip']} {('— ' + h['hostname']) if h['hostname'] else ''}")
            if "ssh_host_key_type" in h and h["ssh_host_key_type"]:
                lines.append(f"- **SSH key type:** {h['ssh_host_key_type']}")
            lines.append("\n| Puerto | Servicio | Versión |")
            lines.append("|---|---|---|")
            for p in h["open_ports"]:
                lines.append(f"| {p['port']} | {p['service']} | {p['version']} |")
            lines.append("")

    # --- Brute force ---
    if "brute_force" in data:
        lines.append("---\n## 3. Brute Force SSH\n")
        if data["brute_force"]:
            lines.append("| IP | Intentos |")
            lines.append("|---|---|")
            for ip, count in data["brute_force"]:
                lines.append(f"| {ip} | {count} |")
        else:
            lines.append("No se detectaron ataques de fuerza bruta.")

    # --- Web analysis ---
    if "web" in data:
        web = data["web"]
        lines.append("\n---\n## 4. Análisis de Tráfico Web\n")
        lines.append("### Top IPs\n")
        lines.append("| IP | Requests |")
        lines.append("|---|---|")
        for ip, count in web["top_ips"]:
            lines.append(f"| {ip} | {count} |")

        lines.append("\n### Status Codes\n")
        lines.append("| Status | Count |")
        lines.append("|---|---|")
        for status, count in sorted(web["status_distribution"].items()):
            lines.append(f"| {status} | {count} |")

        lines.append(f"\n### Requests Sospechosas ({len(web['suspicious_requests'])})\n")
        if web["suspicious_requests"]:
            lines.append("| IP | Path | Status |")
            lines.append("|---|---|---|")
            for r in web["suspicious_requests"]:
                lines.append(f"| {r['ip']} | `{r['path']}` | {r['status']} |")
        else:
            lines.append("Ninguna detectada.")

    # --- Anomalías ---
    if "anomalies" in data:
        lines.append("\n---\n## 5. Anomalías de Tráfico (3-sigma)\n")
        if data["anomalies"]:
            for a in data["anomalies"]:
                lines.append(f"- {a}")
        else:
            lines.append("Sin anomalías detectadas.")

    lines.append("\n---\n*Reporte generado automáticamente por recon.py*")

    with open(output, "w") as f:
        f.write("\n".join(lines))
    log(f"[+] Reporte guardado en {output}")

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon tool integrado")
    parser.add_argument("--target",  help="IP o rango a escanear (ej: 127.0.0.1)")
    parser.add_argument("--ports",   default="1-1024", help="Puertos (ej: 1-1024 o 22,80,443)")
    parser.add_argument("--rate",    type=int, default=200, help="Concurrencia máxima")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout por puerto")
    parser.add_argument("--nmap",    action="store_true", help="Correr nmap -sV")
    parser.add_argument("--ssh",     action="store_true", help="Enriquecer con ssh-keyscan")
    parser.add_argument("--auth",    default=None, help="Archivo auth.log")
    parser.add_argument("--access",  default=None, help="Archivo access.log")
    parser.add_argument("--output",  default="results.json", help="JSON de salida")
    parser.add_argument("--report",  default="report.md", help="Reporte markdown")
    args = parser.parse_args()

    data = {}
    now = datetime.datetime.now().isoformat()

    # 1. Port scan
    if args.target:
        ports = parse_ports(args.ports)
        open_ports, elapsed = run_port_scan(args.target, ports, args.rate, args.timeout)
        data["port_scan"] = {
            "target": args.target,
            "timestamp": now,
            "elapsed": elapsed,
            "open_ports": open_ports
        }

    # 2. nmap
    if args.nmap and args.target:
        xml_path = run_nmap(args.target)
        if xml_path:
            hosts = parse_nmap_xml(xml_path)
            if args.ssh:
                for host in hosts:
                    if any(p["port"] == 22 for p in host["open_ports"]):
                        log(f"[*] ssh-keyscan {host['ip']}...")
                        host["ssh_host_key_type"] = get_ssh_key_type(host["ip"])
            data["hosts"] = hosts
            log(f"[+] {len(hosts)} hosts encontrados")

    # 3. Auth log
    if args.auth:
        log(f"[*] Analizando {args.auth}...")
        data["brute_force"] = detect_brute_force(args.auth)
        log(f"[+] IPs sospechosas: {len(data['brute_force'])}")

    # 4. Access log
    if args.access:
        log(f"[*] Analizando {args.access}...")
        data["web"] = analyze_access_log(args.access)
        data["anomalies"] = detect_traffic_spikes(args.access)
        log(f"[+] Requests sospechosas: {len(data['web']['suspicious_requests'])}")
        log(f"[+] Anomalías: {len(data['anomalies'])}")

    # 5. Guardar JSON
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)
    log(f"[+] Resultados guardados en {args.output}")

    # 6. Generar reporte
    generate_report(data, args.report)

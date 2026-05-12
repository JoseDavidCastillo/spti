import xml.etree.ElementTree as ET
import json
import argparse
import subprocess

# --- B: Parsear XML de nmap ---
def parse_scan(xml_path):
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

# --- C: ssh-keyscan para hosts con puerto 22 ---
def get_ssh_key_type(ip):
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", "3", ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]  # ej: ecdsa-sha2-nistp256, ssh-ed25519
        return "no-key-found"
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception as e:
        return f"error: {str(e)}"

def enrich_ssh(hosts):
    for host in hosts:
        has_ssh = any(p["port"] == 22 for p in host["open_ports"])
        if has_ssh:
            print(f"[*] ssh-keyscan en {host['ip']}...")
            host["ssh_host_key_type"] = get_ssh_key_type(host["ip"])
        else:
            host["ssh_host_key_type"] = None
    return hosts

# --- Main ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parser de nmap XML con enriquecimiento SSH")
    parser.add_argument("--input", required=True, help="Archivo scan.xml de nmap")
    parser.add_argument("--output", default=None, help="Archivo JSON de salida (ej: hosts.json)")
    parser.add_argument("--ssh", action="store_true", help="Enriquecer con ssh-keyscan")
    args = parser.parse_args()

    print(f"[*] Parseando {args.input}...")
    hosts = parse_scan(args.input)

    if not hosts:
        print("[!] No se encontraron hosts con puertos abiertos en el XML.")
        print("[!] Asegúrate de que nmap encontró hosts activos.")
        exit(1)

    print(f"[+] Hosts encontrados: {len(hosts)}")

    if args.ssh:
        print("[*] Enriqueciendo con ssh-keyscan...")
        hosts = enrich_ssh(hosts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(hosts, f, indent=2)
        print(f"[+] Guardado en {args.output}")
    else:
        print(json.dumps(hosts, indent=2))

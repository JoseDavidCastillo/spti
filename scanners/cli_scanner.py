import argparse
import asyncio
import socket
import time
import json
import datetime

# --- CLI ---
parser = argparse.ArgumentParser(description="Port scanner")
parser.add_argument("target")
parser.add_argument("--ports", default="1-1024")
parser.add_argument("--rate", type=int, default=200)
parser.add_argument("--timeout", type=float, default=0.5)
parser.add_argument("--output", default=None)
args = parser.parse_args()

# --- Parsear puertos ---
def parse_ports(s):
    ports = []
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(part))
    return ports

# --- Scanner asyncio ---
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

# --- Ejecutar ---
ports = parse_ports(args.ports)
start = time.perf_counter()
open_ports = asyncio.run(scan_host(args.target, ports, args.rate, args.timeout))
elapsed = time.perf_counter() - start

output = {
    "target": args.target,
    "scan_time_seconds": round(elapsed, 2),
    "timestamp": datetime.datetime.now().isoformat(),
    "open_ports": open_ports
}

if args.output:
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Resultado guardado en {args.output}")
else:
    print(json.dumps(output, indent=2))

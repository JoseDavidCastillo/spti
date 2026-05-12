from concurrent.futures import ThreadPoolExecutor
import socket, time, json, argparse

def scan_port(args):
    host, port, timeout = args
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

# Prueba con distintos workers y tabula los resultados
for workers in [50, 200, 500]:
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = ex.map(scan_port, [("127.0.0.1", p, 0.5) for p in range(1, 1025)])
    elapsed = time.perf_counter() - start
    print(f"workers={workers}: {elapsed:.2f}s")

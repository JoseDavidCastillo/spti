from collections import defaultdict
from pathlib import Path
import re
import argparse

AUTH_FAIL = re.compile(r"Failed password for \S+ from (\d+\.\d+\.\d+\.\d+)")

def detect_brute_force(log_path, threshold=10):
    attempts = defaultdict(int)
    for line in Path(log_path).open():
        if m := AUTH_FAIL.search(line):
            attempts[m.group(1)] += 1
    suspects = [(ip, count) for ip, count in attempts.items() if count >= threshold]
    return sorted(suspects, key=lambda x: -x[1])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Análisis de auth.log")
    parser.add_argument("--input", default="auth.log", help="Archivo auth.log")
    parser.add_argument("--threshold", type=int, default=10, help="Intentos mínimos para reportar")
    args = parser.parse_args()

    print(f"[*] Analizando {args.input}...")
    suspects = detect_brute_force(args.input, args.threshold)

    if not suspects:
        print("[+] No se encontraron IPs sospechosas.")
    else:
        print(f"\n[!] IPs con más de {args.threshold} intentos fallidos:\n")
        print(f"{'IP':<20} {'Intentos':>10}")
        print("-" * 32)
        for ip, count in suspects:
            print(f"{ip:<20} {count:>10}")

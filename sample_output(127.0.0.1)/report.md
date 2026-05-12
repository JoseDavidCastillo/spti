# Security Recon Report

Generado: 2026-05-11 22:55:44

---
## 1. Port Scan

- **Target:** 127.0.0.1
- **Tiempo:** 0.13s
- **Puertos abiertos:** []

---
## 3. Brute Force SSH

| IP | Intentos |
|---|---|
| 185.220.101.5 | 258 |
| 45.33.32.156 | 214 |
| 10.0.0.2 | 12 |

---
## 4. Análisis de Tráfico Web

### Top IPs

| IP | Requests |
|---|---|
| 10.0.0.1 | 1765 |
| 66.249.66.1 | 625 |
| 45.33.32.156 | 317 |
| 185.220.101.5 | 291 |
| 192.168.1.50 | 183 |

### Status Codes

| Status | Count |
|---|---|
| 200 | 3099 |
| 403 | 33 |
| 500 | 49 |

### Requests Sospechosas (95)

| IP | Path | Status |
|---|---|---|
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 192.168.1.50 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 403 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 500 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 500 |
| 185.220.101.5 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 185.220.101.5 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 403 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 192.168.1.50 | `/admin/../../../etc/passwd` | 403 |
| 192.168.1.50 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 185.220.101.5 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 185.220.101.5 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 500 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 403 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 403 |
| 185.220.101.5 | `/admin/../../../etc/passwd` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 200 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 500 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 185.220.101.5 | `/admin/../../../etc/passwd` | 403 |
| 45.33.32.156 | `/admin/../../../etc/passwd` | 500 |
| 192.168.1.50 | `/admin/../../../etc/passwd` | 403 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 200 |
| 45.33.32.156 | `/admin/../../../etc/passwd` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 185.220.101.5 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 403 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 185.220.101.5 | `/search?q=<script>alert(1)</script>` | 500 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 200 |
| 45.33.32.156 | `/admin/../../../etc/passwd` | 403 |

---
## 5. Anomalías de Tráfico (3-sigma)

- [ANOMALY] 11/May/2026-03 — 950 requests (z=4.7σ, threshold=3.0σ)

---
*Reporte generado automáticamente por recon.py*
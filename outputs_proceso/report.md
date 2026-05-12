# Security Analysis Report

Generado: 2026-05-11 22:41:41

- Auth log: `auth.log`
- Access log: `access.log`

---

## 1. Brute Force en SSH

Se encontraron **3** IPs con más de 10 intentos fallidos:

| IP | Intentos |
|---|---|
| 185.220.101.5 | 258 |
| 45.33.32.156 | 214 |
| 10.0.0.2 | 12 |

---

## 2. Top IPs en Tráfico Web

| IP | Requests |
|---|---|
| 10.0.0.1 | 1765 |
| 66.249.66.1 | 625 |
| 45.33.32.156 | 317 |
| 185.220.101.5 | 291 |
| 192.168.1.50 | 183 |

---

## 3. Distribución de Status Codes

| Status | Count |
|---|---|
| 200 | 3099 |
| 403 | 33 |
| 500 | 49 |

---

## 4. Requests Sospechosas

Se detectaron **95** requests con patrones de ataque:

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

Se detectaron **1** horas anómalas:

- [ANOMALY] 11/May/2026-03 — 950 requests (z=4.7σ, threshold=3.0σ)

---

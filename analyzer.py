# analyzer.py

from collections import defaultdict
import os

ip_counter = defaultdict(int)
login_counter = defaultdict(int)
suspicious_paths = {"/admin", "/secret", "/config", "/backup"}
suspicious_hits = []

# Make sure reports folder exists
os.makedirs("reports", exist_ok=True)

with open("logs/access.log", "r") as file:
    for line in file:
        parts = line.strip().split()

        if len(parts) < 4:
            continue

        ip = parts[0]
        endpoint = parts[2]
        status = parts[3]

        ip_counter[ip] += 1

        if endpoint == "/login":
            login_counter[ip] += 1

        if endpoint in suspicious_paths:
            suspicious_hits.append((ip, endpoint, status))

sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)

with open("reports/report.txt", "w") as report:
    report.write("=== TOP IPS ===\n")
    for ip, count in sorted_ips:
        report.write(f"{ip} => {count}\n")

    report.write("\n=== BRUTE FORCE DETECTION ===\n")
    brute_force_found = False
    for ip, count in login_counter.items():
        if count > 3:
            report.write(f"[ALERT] Possible brute force from {ip} | login hits: {count}\n")
            brute_force_found = True

    if not brute_force_found:
        report.write("No brute force detected.\n")

    report.write("\n=== SUSPICIOUS PATHS ===\n")
    if suspicious_hits:
        for ip, endpoint, status in suspicious_hits:
            report.write(f"[SCAN] {ip} requested {endpoint} | status: {status}\n")
    else:
        report.write("No suspicious paths detected.\n")

print("Analysis complete. Report saved to reports/report.txt")

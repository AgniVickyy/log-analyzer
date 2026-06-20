import re
from pathlib import Path
from collections import defaultdict

log_file = Path("logs/access.log")
report_file = Path("reports/report.txt")

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)


def parse_log(line):
    match = pattern.match(line)

    if match:
        return match.groupdict()

    return None


def main():

    if not log_file.exists():
        print("Log file not found")
        return

    report_file.parent.mkdir(exist_ok=True)

    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    status_counts = defaultdict(int)

    login_attempts = defaultdict(int)
    not_found_counts = defaultdict(int)

    suspicious_paths = {
        "/admin",
        "/wp-admin",
        "/config",
        "/backup",
        "/.env",
        "/secret"
    }

    suspicious_requests = []

    bad_lines = 0

    with open(log_file, "r") as f:

        for line in f:

            data = parse_log(line.strip())

            if not data:
                bad_lines += 1
                continue

            ip = data["ip"]
            endpoint = data["endpoint"]
            status = data["status"]

            ip_counts[ip] += 1
            endpoint_counts[endpoint] += 1
            status_counts[status] += 1

            if endpoint == "/login":
                login_attempts[ip] += 1

            if endpoint in suspicious_paths:
                suspicious_requests.append(
                    (ip, endpoint, status)
                )

            if status == "404":
                not_found_counts[ip] += 1

    top_ips = sorted(
        ip_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )

    top_endpoints = sorted(
        endpoint_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )

    with open(report_file, "w") as report:

        report.write("Top IPs\n\n")

        for ip, count in top_ips:
            report.write(f"{ip}: {count}\n")

        report.write("\n")

        report.write("Top Endpoints\n\n")

        for endpoint, count in top_endpoints:
            report.write(f"{endpoint}: {count}\n")

        report.write("\n")

        report.write("Status Codes\n\n")

        for status, count in status_counts.items():
            report.write(f"{status}: {count}\n")

        report.write("\nAlerts\n\n")

        for ip, count in login_attempts.items():

            if count >= 5:
                report.write(
                    f"High login activity from {ip} ({count} attempts)\n"
                )

        for ip, endpoint, status in suspicious_requests:

            report.write(
                f"Sensitive path access: {ip} -> {endpoint} ({status})\n"
            )

        for ip, count in not_found_counts.items():

            if count >= 3:

                report.write(
                    f"Multiple 404 responses from {ip} ({count})\n"
                )

        report.write(f"\nMalformed lines: {bad_lines}\n")

    print("Done")
    print(f"Report saved to {report_file}")


if __name__ == "__main__":
    main()

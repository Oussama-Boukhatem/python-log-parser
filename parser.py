import re
from detectors.detection_rules import detect_brute_force, detect_multiple_invalid_users, detect_root_login

def parse_log_file(file_path):
    log_events = []

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            timestamp = line[:15]

            event_match = re.search(r"(Failed password|Accepted password)", line)
            event = event_match.group(1) if event_match else "Unknown"

            user_match = re.search(r"for (?:invalid user )?(\w+)", line)
            user = user_match.group(1) if user_match else "Unknown"

            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else "Unknown"

            log_events.append({
                "timestamp": timestamp,
                "ip": ip,
                "event": event,
                "user": user
            })

        return log_events

if __name__ == "__main__":
    logs = parse_log_file("logs/sample_auth.log")
    for entry in logs:
        print(entry)

    print("\n=== DETECTION ALERTS ===")

    alerts = []
    alerts += detect_brute_force(logs)
    alerts += detect_multiple_invalid_users(logs)
    alerts += detect_root_login(logs)

    for alert in alerts:
        print(alert)
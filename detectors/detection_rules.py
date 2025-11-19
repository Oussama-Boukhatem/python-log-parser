from collections import defaultdict

def detect_brute_force(log_events, threshold = 5):
    failed_counts = defaultdict(int)
    for event in log_events:
        if event["event"] == "Failed password":
            failed_counts[event["ip"]] += 1

    alerts = []
    for ip, count in failed_counts.items():
        if count > threshold:
            alerts.append(f"[ALERT] Possible brute-force attack from {ip} ({count} failed attempts)")
        return alerts
    
def detect_multiple_invalid_users(log_events, threshold = 3):
    ip_users = defaultdict(set)
    for event in log_events:
        if event["event"] == "Failed password":
            ip_users[event["ip"]].add(event["user"])

    alerts = []
    for ip, users in ip_users.items():
        if len(users) >= threshold:
            alerts.append(f"[ALERT] Multiple invalid usernames from {ip}: {', '.join(users)}")
    return alerts

def detect_root_login(log_events):
    alerts = []
    for event in log_events:
        if event["event"] == "Failed password" and event["user"] == "root":
            alerts.append(f"[ALERT] Root login attempt from {event['ip']}")

    return alerts
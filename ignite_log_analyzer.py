import re
from pathlib import Path

# Pattern: HH:mm:ss.SSS [thread] LEVEL logger - message
LOG_PATTERN = re.compile(r'(?P<time>\d{2}:\d{2}:\d{2}\.\d{3}) \[.*?\] \w+ .*? - (?P<msg>.*)')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PORT_PATTERN = re.compile(r':(\d{4,5})\b')
KEYWORDS = ['join', 'connect', 'TcpDiscovery', 'failure', 'reconnect', 'spi', 'cluster', 'vmip', 'multicast']

def extract_events(file_path):
    events = []
    with open(file_path, 'r') as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if not match:
                continue
            msg = match.group("msg")
            if any(word.lower() in msg.lower() for word in KEYWORDS):
                time = match.group("time")
                ips = IP_PATTERN.findall(msg)
                ports = PORT_PATTERN.findall(msg)
                events.append({
                    "time": time,
                    "msg": msg.strip(),
                    "ips": ips,
                    "ports": ports
                })
    return events

def analyze(log1_events, log2_events):
    # Extract unique IPs and ports
    ips1 = {ip for e in log1_events for ip in e['ips']}
    ips2 = {ip for e in log2_events for ip in e['ips']}
    common_ips = ips1 & ips2

    ports1 = {p for e in log1_events for p in e['ports']}
    ports2 = {p for e in log2_events for p in e['ports']}
    common_ports = ports1 & ports2

    print("=== Shared Information ===")
    print(f"[+] Shared IPs: {common_ips}" if common_ips else "[-] No shared IPs")
    print(f"[+] Shared Ports: {common_ports}" if common_ports else "[-] No shared ports")
    print("")

    print("=== Suspicious Entries in ignite1.log ===")
    for e in log1_events:
        print(f"{e['time']} | {e['msg']}")

    print("\n=== Suspicious Entries in ignite2.log ===")
    for e in log2_events:
        print(f"{e['time']} | {e['msg']}")

if __name__ == "__main__":
    log1_path = Path("ignite1.log")
    log2_path = Path("ignite2.log")

    if not log1_path.exists() or not log2_path.exists():
        print("Error: One or both log files not found.")
        exit(1)

    log1 = extract_events(log1_path)
    log2 = extract_events(log2_path)

    analyze(log1, log2)

#!/usr/bin/env python3
import csv
import subprocess
from collections import Counter
from pathlib import Path
PCAP_DIR = Path.home() / "assignment" / "pcap_files"
OUT_DIR = Path.home() / "assignment" / "analysis"
OUT_DIR.mkdir(parents=True, exist_ok=True)
def run(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.stdout
def extract_http_requests(pcap, out_csv):
    cmd = f'tshark -r "{pcap}" -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri'
    out = run(cmd)
    rows = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) >= 3:
            rows.append((parts[0], parts[1], parts[2]))
    with open(out_csv, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "host", "uri"])
        writer.writerows(rows)
def extract_dns_queries(pcap, out_csv):
    cmd = f'tshark -r "{pcap}" -Y "dns.qry.name" -T fields -e ip.src -e dns.qry.name'
    out = run(cmd)
    rows = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) >= 2:
            rows.append((parts[0], parts[1]))
    with open(out_csv, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "dns_query"])
        writer.writerows(rows)
def top_talkers(pcap, out_csv):
    cmd = f'tshark -r "{pcap}" -T fields -e ip.src -e ip.dst'
    out = run(cmd)
    c = Counter()
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) >= 1 and parts[0]:
            c[parts[0]] += 1
        if len(parts) >= 2 and parts[1]:
            c[parts[1]] += 1
    with open(out_csv, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "packets"])
        for ip, cnt in c.most_common():
            writer.writerow([ip, cnt])
def protocol_counts(pcap, out_csv):
    cmd = f'tshark -r "{pcap}" -T fields -e _ws.col.Protocol'
    out = run(cmd)
    c = Counter()
    for line in out.splitlines():
        proto = line.strip()
        if proto:
            c[proto] += 1
    with open(out_csv, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["protocol", "count"])
        for proto, cnt in c.most_common():
            writer.writerow([proto, cnt])
def main():
    pcap = PCAP_DIR / "task2/all_traffic.pcap"
    if not pcap.exists():
        print("all_traffic.pcap not found in", PCAP_DIR)
        return
    extract_http_requests(str(pcap), OUT_DIR / "http_requests.csv")
    extract_dns_queries(str(pcap), OUT_DIR / "dns_queries.csv")
    top_talkers(str(pcap), OUT_DIR / "top_talkers.csv")
    protocol_counts(str(pcap), OUT_DIR / "protocol_counts.csv")
    print("Outputs written to", OUT_DIR)
if __name__ == "__main__":
    main()

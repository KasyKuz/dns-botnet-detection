#!/usr/bin/env python3

import argparse
import os
from collections import Counter
from scapy.all import rdpcap
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP


def analyze_dns_requests(input_file: str, top_n: int = 15):
    if not os.path.exists(input_file):
        print(f"Файл {input_file} не найден")
        return Counter(), 0

    packets = rdpcap(input_file)
    ip_counter = Counter()
    dns_queries = 0

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(DNSQR):
            src_ip = packet[IP].src
            ip_counter[src_ip] += 1
            dns_queries += 1

    print(f"Всего DNS-запросов: {dns_queries}")
    print(f"Уникальных IP: {len(ip_counter)}")

    if ip_counter:
        print(f"\nТоп-{top_n} IP:")
        for i, (ip, count) in enumerate(ip_counter.most_common(top_n), 1):
            percent = (count / dns_queries) * 100 if dns_queries else 0
            print(f"{i:2}. {ip:15} -> {count:6} ({percent:.1f}%)")

    return ip_counter, dns_queries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Входной PCAP файл')
    parser.add_argument('-n', '--top', type=int, default=15)

    args = parser.parse_args()
    analyze_dns_requests(args.input, args.top)


if __name__ == "__main__":
    main()
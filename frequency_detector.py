#!/usr/bin/env python3

import argparse
import os
import json
import statistics
from collections import defaultdict
from datetime import datetime
from scapy.all import rdpcap
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP


def find_consecutive_series(timestamps: list, max_gap: float = 60.0) -> list:
    if len(timestamps) < 2:
        return []

    series = []
    current = 1

    for i in range(1, len(timestamps)):
        if timestamps[i] - timestamps[i-1] <= max_gap:
            current += 1
        else:
            if current >= 2:
                series.append(current)
            current = 1

    if current >= 2:
        series.append(current)

    return series


def analyze_frequency(pcap_file: str, min_requests: int = 100, max_interval: float = 300.0) -> dict:
    if not os.path.exists(pcap_file):
        print(f"Файл {pcap_file} не найден")
        return {}

    packets = rdpcap(pcap_file)
    ip_domains = defaultdict(lambda: defaultdict(list))

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(DNSQR):
            src_ip = packet[IP].src
            timestamp = packet.time
            try:
                domain = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                ip_domains[src_ip][domain].append(timestamp)
            except Exception:
                continue

    suspicious = {}

    for src_ip, domains in ip_domains.items():
        for domain, timestamps in domains.items():
            if len(timestamps) < min_requests:
                continue

            timestamps.sort()
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]

            if not intervals:
                continue

            try:
                mean_int = statistics.mean(intervals)
                if mean_int > max_interval:
                    continue

                long_count = sum(1 for i in intervals if i > max_interval)
                long_ratio = long_count / len(intervals)

                if long_ratio > 0.1:
                    continue

                series = find_consecutive_series(timestamps, 60.0)
                max_series = max(series) if series else 0

                suspicious[(src_ip, domain)] = {
                    'count': len(timestamps),
                    'mean_interval': round(mean_int, 2),
                    'max_interval': round(max(intervals), 2),
                    'long_ratio': round(long_ratio, 4),
                    'max_consecutive': max_series,
                    'first_seen': datetime.fromtimestamp(min(timestamps)).strftime('%Y-%m-%d %H:%M:%S'),
                    'last_seen': datetime.fromtimestamp(max(timestamps)).strftime('%Y-%m-%d %H:%M:%S'),
                    'duration_hours': round((max(timestamps) - min(timestamps)) / 3600, 2)
                }
            except statistics.StatisticsError:
                continue

    return suspicious


def print_results(suspicious: dict) -> None:
    if not suspicious:
        print("Частые запросы не обнаружены")
        return

    print(f"\nОбнаружено {len(suspicious)} пар:")
    sorted_items = sorted(suspicious.items(), key=lambda x: x[1]['count'], reverse=True)

    for (src_ip, domain), data in sorted_items[:20]:
        print(f"IP: {src_ip} -> {domain}")
        print(f"  Запросов: {data['count']}")
        print(f"  Средний интервал: {data['mean_interval']} сек")
        if data['max_consecutive'] >= 4:
            print(f"  Серии: до {data['max_consecutive']} подряд")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Входной PCAP файл')
    parser.add_argument('-m', '--min-requests', type=int, default=100)
    parser.add_argument('-i', '--max-interval', type=float, default=300.0)
    parser.add_argument('-o', '--output', help='Выходной JSON файл')

    args = parser.parse_args()

    suspicious = analyze_frequency(args.input, args.min_requests, args.max_interval)
    print_results(suspicious)

    if args.output and suspicious:
        out_data = {f"{ip}|{domain}": data for (ip, domain), data in suspicious.items()}
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(out_data, f, indent=2, ensure_ascii=False)
        print(f"Сохранено: {args.output}")


if __name__ == "__main__":
    main()
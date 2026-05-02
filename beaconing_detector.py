
import argparse
import os
import json
import statistics
from collections import defaultdict
from datetime import datetime
from scapy.all import rdpcap
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP


def load_ip_list(file_path: str) -> set:
    if not file_path:
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        print(f"Ошибка загрузки IP: {e}")
        return None


def analyze_beaconing(pcap_file: str, target_ips: set = None, cv_threshold: float = 0.3, min_requests: int = 10) -> dict:
    if not os.path.exists(pcap_file):
        print(f"Файл {pcap_file} не найден")
        return {}

    packets = rdpcap(pcap_file)
    ip_domains = defaultdict(lambda: defaultdict(list))

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(DNSQR):
            src_ip = packet[IP].src

            if target_ips is not None and src_ip not in target_ips:
                continue

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
                stdev_int = statistics.stdev(intervals) if len(intervals) > 1 else 0
                cv = stdev_int / mean_int if mean_int > 0 else float('inf')

                if cv < cv_threshold:
                    suspicious[(src_ip, domain)] = {
                        'count': len(timestamps),
                        'mean_interval': round(mean_int, 2),
                        'std_interval': round(stdev_int, 2),
                        'cv': round(cv, 4),
                        'first_seen': datetime.fromtimestamp(min(timestamps)).strftime('%Y-%m-%d %H:%M:%S'),
                        'last_seen': datetime.fromtimestamp(max(timestamps)).strftime('%Y-%m-%d %H:%M:%S')
                    }
            except statistics.StatisticsError:
                continue

    return suspicious


def print_results(suspicious: dict) -> None:
    if not suspicious:
        print("Beaconing не обнаружен")
        return

    print(f"\nОбнаружено {len(suspicious)} пар:")
    for (src_ip, domain), data in suspicious.items():
        print(f"IP: {src_ip} -> {domain}")
        print(f"  Запросов: {data['count']}")
        print(f"  Средний интервал: {data['mean_interval']} сек")
        print(f"  CV: {data['cv']}")
        print("-" * 50)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Входной PCAP файл')
    parser.add_argument('--ip-list', '-i', help='Файл со списком IP для анализа (опционально)')
    parser.add_argument('-t', '--threshold', type=float, default=0.3)
    parser.add_argument('-m', '--min-requests', type=int, default=10)
    parser.add_argument('-o', '--output', help='Выходной JSON файл')

    args = parser.parse_args()

    target_ips = load_ip_list(args.ip_list) if args.ip_list else None

    suspicious = analyze_beaconing(args.input, target_ips, args.threshold, args.min_requests)
    print_results(suspicious)

    if args.output and suspicious:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(suspicious, f, indent=2, ensure_ascii=False, default=str)
        print(f"Сохранено: {args.output}")


if __name__ == "__main__":
    main()


import argparse
import os
from scapy.all import rdpcap, wrpcap
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP


def load_whitelist(file_path: str) -> list:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Ошибка: {e}")
        return []


def filter_dns_pcap(input_file: str, output_file: str, whitelist_file: str) -> None:
    whitelist_ips = load_whitelist(whitelist_file)
    if not whitelist_ips:
        print("Белый список пуст")
        return

    if not os.path.exists(input_file):
        print(f"Файл {input_file} не найден")
        return

    packets = rdpcap(input_file)
    filtered_packets = []
    removed_count = 0

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(DNSQR):
            src_ip = packet[IP].src
            if src_ip in whitelist_ips:
                removed_count += 1
                continue
        filtered_packets.append(packet)

    wrpcap(output_file, filtered_packets)
    print(f"Сохранено: {output_file}")
    print(f"Исходных: {len(packets)}, Удалено: {removed_count}, Осталось: {len(filtered_packets)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Входной PCAP файл')
    parser.add_argument('output', help='Выходной PCAP файл')
    parser.add_argument('--whitelist', '-w', required=True, help='Файл со списком IP')

    args = parser.parse_args()
    filter_dns_pcap(args.input, args.output, args.whitelist)


if __name__ == "__main__":
    main()
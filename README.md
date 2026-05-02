Анализ DNS-трафика для выявления инфицированных машин в локальной сети.

Инструментарий:

pcap_filter.py - Фильтрация IP из белого списка
ip_statistics.py - Статистика DNS-запросов по IP 
detailed_report.py - Детальный отчет по указанным IP 
beaconing_detector.py - Поиск периодических запросов (CV < порога) 
frequency_detector.py - Поиск частых запросов и серий подряд 

1. Фильтрация белого списка
```
python pcap_filter.py input.pcap filtered.pcap -w whitelist.txt
```
2. Статистикапо IP
```
python ip_statistics.py filtered.pcap -n 20
```
4. Детальный отчет
```
python detailed_report.py filtered.pcap -i suspicious_ips.txt -o report.txt
```
6. Анализ периодичности запросов
```
python beaconing_detector.py filtered.pcap -t 0.3 -m 10 -o beaconing.json
```
8. Частотный анализ
```
python frequency_detector.py filtered.pcap -m 100 -i 300 -o frequency.json
```

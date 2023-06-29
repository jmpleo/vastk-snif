### How to use?

#### Python Requirements:

``` 
scapy==2.5.0
beautifulsoup4==4.12.2
```

#### 1. Capture:

Open http://www.example.com or other non-encryption website, then capture this:

```bash
cd sniffer
sudo python sniffer.py # capture in ./capture.pcap
```

#### 2. Restore pages:

```bash
python restore-html.py test.pcap report
```


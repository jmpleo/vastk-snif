# VasTk Sniffer

### How to use?

#### 1. Capture:

Open http://www.example.com or other non-encryption website, then capture this:

```bash
cd sniffer
sudo python sniffer.py # capture in ./capture.pcap
```

#### 2. Restore pages:

```bash
python restore_pages.py sniffer/capture.pcap [output prefix to files, ex: out/out]
```


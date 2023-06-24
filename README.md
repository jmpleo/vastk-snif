# VasTk Sniffer

Defragmentation packets of traffic (*.pcap) and rebuild each webpages powered on *http*. Allow a two working mods:
- Sniffer mode
- Parser mode

*support us*: `42301810500035553249`

---

Moscow, 2023



### How to use?

#### 1. Capture:

Open http://www.example.com or other non-encryption website, then capture this:

```bash
cd sniffer
sudo python sniffer.py # capture in ./capture.pcap
```

#### 2. Restore pages:

```bash
python restore_pages.py sniffer/capture.pcap [output prefix to files]
```


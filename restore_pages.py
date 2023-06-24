import argparse
from scapy.all import rdpcap, gzip
from scapy.layers.inet import TCP

parser = argparse.ArgumentParser(description='Restore HTML payload from TCP packets')
parser.add_argument('input_file', metavar='INPUT_FILE', help='input PCAP file')
parser.add_argument('output_files_prefix', metavar='OUTPUT_FILES_PREFIX', help='output HTML file')

args = parser.parse_args()

packets = rdpcap(args.input_file)[TCP]

payload = ''
count = 0
for packet in packets:
    if packet.haslayer(TCP) and packet[TCP].payload:
        raw = packet[TCP].payload.load
        content_encoding = None
        for header in raw.split(b'\r\n'):
            if header.startswith(b'Content-Encoding'):
                content_encoding = header.split(b': ')[1].decode('utf-8')
                break
        if content_encoding == 'gzip':
            s_str = gzip.decompress(raw[raw.index(b'\r\n\r\n')+4:]).decode('utf-8')
        else:
            s_str = raw.decode('utf-8')
        count += 1
        payload += s_str
        with open(f"{args.output_files_prefix}-{count}.html", 'w') as f:
            f.write(s_str)

print(f'found {count} pages')
with open(f"{args.output_files_prefix}.html", 'w') as f:
    f.write(payload)


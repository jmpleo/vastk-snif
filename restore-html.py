from scapy.layers.inet import TCP
from scapy.all import rdpcap

import gzip
import zlib
import brotli

import argparse
import re

def get_tcp_session(packets):
    sessions = {}

    for packet in packets:
        if TCP in packet and packet[TCP].payload:
            session = (packet[TCP].sport, packet[TCP].dport)
            sessions[session] = sessions.get(session, b'') + packet[TCP].payload.load

    return sessions


def get_http_content(sessions):
    content = {}

    for session, payload in sessions.items():
        if b'\r\n\r\n' not in payload:
            continue
        else:
            header, body = payload.split(b'\r\n\r\n', 1)
            enc_match = re.search(b'Content-Encoding: ([^\r\n]*)', header)

            if len(body) and enc_match:
                encoding = enc_match.group(1).decode('utf-8')
                try:
                    if encoding == 'gzip':
                        content[session] = content.get(session, '') + gzip.decompress(body).decode('utf-8')
                    elif encoding == 'deflate':
                        content[session] = content.get(session, '') + zlib.decompress(body).decode('utf-8')
                    elif encoding == 'br':
                        content[session] = content.get(session, '') + brotli.decompress(body).decode('utf-8')
                    else:
                        content[session] = content.get(session, '') + body.decode('utf-8')
                except Exception as e:
                    continue
            else:
                continue

    return content

parser = argparse.ArgumentParser(
    description='Restore HTML payload from TCP packets'
)
parser.add_argument(
    'input_file',
    metavar='INPUT_FILE',
    help='input PCAP file'
)
args = parser.parse_args()
packets = rdpcap(args.input_file)[TCP]

contents = get_http_content(get_tcp_session(packets))

for session in contents:
    with open(f"{session[0]}-{session[1]}.html", "w", encoding="utf-8") as f:
        f.write(contents[session])


from scapy.layers.inet import TCP
from scapy.all import rdpcap

import gzip
import zlib
import brotli
from bs4 import BeautifulSoup

import argparse
import re

def get_tcp_session(packets):
    sessions = {}

    for packet in packets:
        if TCP in packet and packet[TCP].payload:
            session = (packet[TCP].sport, packet[TCP].dport)
            sessions[session] = re.sub(
                b'(\r\n\r\n)+', b'\r\n\r\n',
                sessions.get(session, b'') + b'\r\n\r\n' + packet[TCP].payload.load)            

    return sessions

def get_http_content(sessions):
    contents = {}

    for session, payload in sessions.items():
        while b'\r\n\r\n' in payload:
            
            header, payload = payload.split(b'\r\n\r\n', 1)
            
            # if b'HTTP' not in header: # and len(payload) and b'HTTP' in payload[:50]:
            #     continue

            # print(f"header: {header}\npayload: {payload[:100]}\nsession: {session}")
            # input()
            
            # if b'\r\n\r\n' in payload:
            #     body, payload = payload.split(b'\r\n\r\n', 1)
            # else:
            #     body = payload
            
            enc_match = re.search(b'Content-Encoding: ([^\r\n]*)', header)

            # print(f"header: {header}\nbody: {body}\nsession: {session}")
            # input()
            if enc_match:
                encoding = enc_match.group(1).decode('utf-8')
                # print(f"encoding: {encoding}")
                # input()
                try:
                    if encoding == 'gzip':
                        contents[session] = contents.get(session, '') + gzip.decompress(payload).decode('utf-8')
                    elif encoding == 'deflate':
                        contents[session] = contents.get(session, '') + zlib.decompress(payload).decode('utf-8')
                    elif encoding == 'br':
                        contents[session] = contents.get(session, '') + brotli.decompress(payload).decode('utf-8')
                    else:
                        contents[session] = contents.get(session, '') + payload.decode('utf-8')
                except Exception as e:
                    continue
            else:
                try:
                    contents[session] = contents.get(session, '') + payload.decode('utf-8')
                except Exception as e:
                    continue

    return contents

def save_content(contents):
    for session, content in contents.items():
        soup = BeautifulSoup(content)
        filename = f"{soup.title.string}.html" if soup.title else f"session_{session[0]}-{session[1]}.out"
        with open(f"{filename}", "w") as f:
            f.write(content)

parser = argparse.ArgumentParser(
    description='Restore HTML payload from TCP packets'
)
parser.add_argument(
    'input_file',
    metavar='INPUT_FILE',
    help='input PCAP file'
)
parser.add_argument(
    'output_prefix',
    metavar='OUTPUT_PREFIX',
    help='prefix for ouput files'
)
args = parser.parse_args()
packets = rdpcap(args.input_file)[TCP]

contents = get_html_content(get_http_content(get_tcp_session(packets)))

for session, content in contents.items():
    soup = BeautifulSoup(content)
    filename = f"{soup.title.string}.html" if soup.title else f"session_{session[0]}-{session[1]}.out"
    with open(f"{args.output_prefix}{filename}", "w", encoding="utf-8") as f:
        f.write(content)


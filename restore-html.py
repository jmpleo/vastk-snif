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
            sessions[session] = (sessions.get(session, b'') + b'\r\n\r\n' + packet[TCP].payload.load
                                ).replace(b'\r\n\r\n\r\n\r\n',b'\r\n\r\n')
            

    return sessions


def get_http_content(sessions):
    contents = {}

    for session, payload in sessions.items():
        while b'\r\n\r\n' in payload:
            header, payload = payload.split(b'\r\n\r\n', 1)
            # print(f"header: {header[:100]}\npayload: {payload[:100]}\nsession: {session}")
            # input()
            if len(payload) and b'HTTP' in payload[:100]:
                continue

            if b'\r\n\r\n' in payload:
                body, payload = payload.split(b'\r\n\r\n', 1)
            else:
                body = payload
            
            enc_match = re.search(b'Content-Encoding: ([^\r\n]*)', header)

            # print(f"header: {header}\nbody: {body}\nsession: {session}")
            # input()
            if enc_match:
                encoding = enc_match.group(1).decode('utf-8')
                # print(f"encoding: {encoding}")
                # input()
                try:
                    if encoding == 'gzip':
                        contents[session] = contents.get(session, '') + gzip.decompress(body).decode('utf-8')
                    elif encoding == 'deflate':
                        contents[session] = contents.get(session, '') + zlib.decompress(body).decode('utf-8')
                    elif encoding == 'br':
                        contents[session] = contents.get(session, '') + brotli.decompress(body).decode('utf-8')
                    else:
                        contents[session] = contents.get(session, '') + body.decode('utf-8')
                except Exception as e:
                    continue
            else:
                try:
                    contents[session] = contents.get(session, '') + body.decode('utf-8')
                except Exception as e:
                    continue

    return contents

def get_html_content(contents):
    html_contents = {}
    for session, content in contents.items():
        if "<!doctype html>" in content.lower():
            html_contents[session] = content
    return html_contents


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

for session in contents:
    with open(f"{args.output_prefix}{session[0]}-{session[1]}.html", "w", encoding="utf-8") as f:
        f.write(contents[session])


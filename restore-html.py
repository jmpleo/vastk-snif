from scapy.layers.inet import TCP
from scapy.all import rdpcap

import gzip
import zlib
import brotli
from bs4 import BeautifulSoup
import itertools
import argparse
import re


def get_tcp_session(packets):
    sessions = {}

    for packet in packets:
        if TCP in packet and packet[TCP].payload:
            session = (packet[TCP].sport, packet[TCP].dport)
            sessions[session] = sessions.get(session, b'') + packet[TCP].payload.load            

    return sessions


def get_http_response(sessions):
    return {
        session : payload
        for session, payload in sessions.items() if session[0] == 80
    }


def choise_bytes_delim(s):
    delim_len = 1
    while True:
        for delim in generate_bytes_string(delim_len):
            if delim not in s:
                return delim
        delim_len += 1

        
def generate_bytes_string(length):
    for s in itertools.product(range(256), repeat=length):
        yield bytes(s)


def split_on_http_mess(http_responses):
    splited = {}
    for session, http_response in http_responses.items():
        delim = choise_bytes_delim(http_response) 
        splited[session] = re.sub(
            b'(?P<http>HTTP\/\d\.\d\s+\d+\s+[\w\s-]+\r\n(?:[\w-]+:\s+.*\r\n)*\r\n)', 
            delim + b'\g<http>',
            http_response
        ).split(delim)[1:]
    return splited


def try_decompres_http_content(splited_http_messeges):
    decompressed_http_content = {}
    for session, http_messeges in splited_http_messeges.items():    
        decompressed_http_content[session] = []
        for http_mess in http_messeges: 
            header, body = http_mess.split(b'\r\n\r\n', 1)
            enc_match = re.search(b'Content-Encoding: ([^\r\n]*)', header)
            # print(f"header: {header}\nbody: {body}\nsession: {session}")
            # input()
            if enc_match:
                encoding = enc_match.group(1).decode('utf-8')
                try:
                    if encoding == 'gzip':
                        decompressed_http_content[session].append(gzip.decompress(body))
                        #decompressed_http_content[session] = { header : gzip.decompress(body) }
                    elif encoding == 'deflate':
                        decompressed_http_content[session].append(zlib.decompress(body))
                        #decompressed_http_content[session] = { header : zlib.decompress(body) }
                    elif encoding == 'br':
                        decompressed_http_content[session].append(brotli.decompress(body))
                        #decompressed_http_content[session] = { header : brotli.decompress(body) }
                    else:
                        decompressed_http_content[session].append(gzip.decompress(body))
                        #decompressed_http_content[session] = { header : gzip.decompress(body) }
                except Exception as e:
                    print(encoding)
                    decompressed_http_content[session].append(body)
                    #decompressed_http_content[session] = { header : body }
    return decompressed_http_content
                

def save_content(contents, output_dir):
    for session, contents in contents.items():
        for i, content in enumerate(contents):
            soup = BeautifulSoup(content)
            filename = f"{soup.title.string}.html" if soup.title else f"session_{session[0]}-{session[1]}-{i}.out"
            with open(f"{output_dir}/{filename}", "w") as f:
                f.write(content.decode('utf-8'))

parser = argparse.ArgumentParser(
    description='Restore HTML payload from TCP packets'
)
parser.add_argument(
    'input_file',
    metavar='INPUT_FILE',
    help='input PCAP file'
)
parser.add_argument(
    'report_dir',
    metavar='REPORT',
    help='report directory for output files'
)
args = parser.parse_args()
packets = rdpcap(args.input_file)[TCP]

save_content(
    try_decompres_http_content(
    split_on_http_mess(
    get_http_response(
    get_tcp_session(packets)))),
    args.report_dir
)

import scapy.all as scapy

def defragment_tcp_packets(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    fragments = {}

    for packet in packets:

        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]

            if ip.flags == 0x01:

                # This is a fragment
                if ip.id not in fragments:
                    fragments[ip.id] = [packet]
                else:
                    fragments[ip.id].append(packet)

            elif ip.flags == 0x00 and ip.id in fragments:

                # This is the last fragment
                fragments[ip.id].append(packet)

                # Combine fragments into a single packet
                combined_packet = scapy.IP()

                for fragment in fragments[ip.id]:
                    combined_packet /= fragment[scapy.IP].payload

                # Remove the original fragments from the list of packets
                packets = [p for p in packets if p not in fragments[ip.id]]

                # Add the combined packet to the list of packets
                packets.append(combined_packet)

                # Remove the ID from the list of fragments
                del fragments[ip.id]
    return packets



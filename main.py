#!/usr/bin/python3
import socket
import os
import ipaddress
import struct

HOST = '10.20.0.224'

protocol_map = { 1: 'ICMP',
                 6 : 'UDP',
                 17: 'TCP'

}

class ICMP():
    def __init__(self, buff=None):
        value = struct.unpack('<BBHHHHHHH4s4s', buff)
        self.ICMP_type = value[0]
        self.ICMP_code = value[1]
        self.src = value[9]
        self.dst = value[10]


class IP():
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.inl = header[0] & 0xF
        self.tos = header[1]
        self.tlen = header[2]
        self.ident = header[3]
        self.ttl = header[5]
        self.protocol = header[6]
        self.checksum = header[7]
        self.src_ip = header[8]
        self.dst_ip = header[9]


def main():
    # create a raw socket and bind to the interface
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))

    # Include the IP header in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Read one packet

    buffer = sniffer.recvfrom(65565)
    ip_data = buffer[0][0:20]
    packet = IP(ip_data)
    print(f"packet ver--> {packet.ver}")
    print(f"packet ihl--> {packet.inl}")
    print('packet source--> '+'.'.join([f'{c}' for c in packet.src_ip]))
    print('packet destination--> ' + '.'.join([f'{c}' for c in packet.dst_ip]))
    print(f'packet protocol--> {protocol_map[packet.protocol]}')

    if packet.protocol == 1:
        icmp_packet = ICMP(buffer[0][20:44])
        print(icmp_packet.ICMP_type)
        print(icmp_packet.ICMP_code)
        print('.'.join(f'{c}' for c in icmp_packet.src))
        print('.'.join(f'{c}' for c in icmp_packet.dst))




    # if we are on windows turn off promiscouos mode

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == '__main__':
    main()

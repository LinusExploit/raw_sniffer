#!/usr/bin/python3
import socket
import os
import ipaddress
import struct
import sys 
import threading
import time 

#Subnet to target
SUBNET = "10.20.0.0/16"

#Magic string we will check ICMP response for
MESSAGE = "PYTHONRULES!"


#this sprays out UDP datagrams with our magic message 
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE,'utf8'),(str(ip), 65212) )




HOST = '10.20.0.224'    

protocol_map = { 1: 'ICMP',
                 6 : 'UDP',
                 17: 'TCP'

}

class ICMP():
    def __init__(self, buff=None):
        value = struct.unpack('<BBHHH', buff)
        self.type = value[0]
        self.code = value[1]
        self.checksum = value[2]
        self.id = value[3]
        self.seq = value[4]


class IP():
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.inl = header[0] & 0xF                    # Inner header length multiple of 4
        self.tos = header[1]
        self.tlen = header[2]
        self.ident = header[3]
        self.ttl = header[5]
        self.protocol = header[6]
        self.checksum = header[7]
        self.src_ip = header[8]
        self.dst_ip = header[9]

        #Human readable IP addresses:
        self.src_iph = ipaddress.ip_address(self.src_ip)
        self.dst_iph = ipaddress.ip_address(self.dst_ip)


class Scanner:
    def __init__(self, host):
        self.host = host 
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        hosts_up = set([f'{str(self.host)}*'])
        try:
            while True:
                #read a packet
                raw_buffer = self.socket.recvfrom(65535)[0]
                #create an ip header from the first 20 bytes 
                ip_header = IP(raw_buffer[0:20])
                #if it is ICMP we want it
                if ip_header.protocol == 1:
                    offset = ip_header.inl * 4
                    buf = raw_buffer[offset:offset +8]
                    icmp_header = ICMP(buf)
                    #check for type 3 and code 
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.src_iph) in ipaddress.IPv4Network(SUBNET):

                            #Make sure it has our magic message 
                            if raw_buffer[len(raw_buffer)- len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_iph)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_iph))
                                    print(f'Hosts Up: {tgt}')

        #handle CTRL-C
        except KeyboardInterrupt:
            if os.name == 'nt':
                self.socket.ioctl(socket.SIORCVALL, socket.RCVALL_OFF)
            
            print("\nUser Interrupted.")
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {SUBNET}')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit





if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.200'
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()

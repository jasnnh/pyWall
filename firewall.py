import pydivert
from pydivertwriter import PydivertWriter
import threading
from time import sleep
import logging 
import json
import hashlib
import codecs
codecs.register_error("strict", codecs.ignore_errors)

LAN_IP = "192.168.1.179"

#now we will Create and configure logger 
logging.basicConfig(filename="std.log", 
					format='%(asctime)s %(message)s', 
					filemode='w') 

#Let us Create an object 
logger=logging.getLogger() 

#Now we are going to Set the threshold of logger to DEBUG 
logger.setLevel(logging.DEBUG) 

ip_whitelist = list()
port_whitelist = list()
port_list = ["80", "81"]
ip_list = ["127.0.0.1"]
syn_packets = dict()
REFRESH_RATE = 10
SYN_PACKET_COUNT = 100  # max {syn}  packet allowed from a certain ip
pcap = PydivertWriter("firewall_log.pcap", sync=True, append=True)


def syn(w, packet):
    packet_ip = packet.src_addr
    
    print(f"[SYN PACKET] FROM {packet_ip} DST ADDRESS: {packet.dst_addr}")
    logger.info(f"[SYN PACKET] FROM {packet_ip} DST ADDRESS: {packet.dst_addr}")
    # adding one to dict value if exist else create one then add
    if packet_ip in syn_packets:
        syn_packets[packet_ip] += 1
    else:
        syn_packets[packet_ip] = 0
        syn_packets[packet_ip] += 1
    # if max count has been reached disallow packet
    if syn_packets[packet_ip] > SYN_PACKET_COUNT:
        print(f"[SYN PACKET] OVER 100 PACKETS FROM SRC ADDRESS: {packet_ip} DST ADDRESS: {packet.dst_addr} IGNORING PACKET")
        logger.info(f"[SYN PACKET] OVER 100 PACKETS FROM SRC ADDRESS: {packet_ip} DST ADDRESS: {packet.dst_addr} IGNORING PACKET")
        # This is here to prevent the pcap file getting too big
        if syn_packets[packet_ip] - SYN_PACKET_COUNT < 10:
            pcap.write(packet)
    else:
        w.send(packet)



# this is not the best way
def DDOS_SYNFLOOD_Refresh():
    global syn_packets
    global REFRESH_RATE

    while True:
        sleep(REFRESH_RATE * 60)
        syn_packets = dict()

def DDOS_SYNFLOOD_PORTBLOCK_LOOP():
    #with pydivert.WinDivert("tcp.Syn or icmp") as w:
    with pydivert.WinDivert("tcp") as w:
        for packet in w:
            if f'{packet.dst_port}' in port_list:
                print(f"[Port blocked] Port: {packet.dst_port}");
                logger.info(f"[Port blocked] Port: {packet.dst_port}")
                continue
            elif f'{packet.dst_addr}' in ip_list:
                print(f"[IP blocked] IP: {packet.dst_addr}");
                logger.info(f"[IP blocked] IP: {packet.dst_addr}")
                continue
            elif packet.icmp:
                print(f"[ICMP Packet] Source Address: {packet.src_addr}");
                logger.info(f"[ICMP Packet Blocked] Source Address: {packet.src_addr}");
            elif packet.tcp.syn:
                if packet.dst_addr != LAN_IP or packet.dst_addr != "127.0.0.1" or packet.dst_addr != "::1":
                    threading.Thread(target=syn(w, packet)).start()
            else:
                w.send(packet)
       
#

threading.Thread(target=DDOS_SYNFLOOD_Refresh).start()
threading.Thread(target=DDOS_SYNFLOOD_PORTBLOCK_LOOP).start()
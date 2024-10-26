from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import numpy as np
from PIL import Image
from pathlib import Path
import os
import argparse
import hashlib
from collections import defaultdict

def SessionAll(pcap_path): #Tunring the pcap file into Session All format
    print(f"pcap_path now: {pcap_path}")
    packets = rdpcap(pcap_path)

    seen_packets_hash = set()
    sessions = defaultdict(bytearray)

    for packet in packets:
        if not packet.haslayer('IP'):
            continue
        ip = packet[IP]
        data = bytes(packet) #keep All imformation
        data_hash = hashlib.md5(data).hexdigest() #transform byte data into hash value on easier purpose
       
        #avoid duplicate packets
        if data_hash in seen_packets_hash: #if hash was seen, then we don't need to process it again
            continue 
        seen_packets_hash.add(data_hash) #else add new hash into set

        src_port = None
        dst_port = None
        proto = None

        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if src_port is not None and dst_port is not None and proto is not None:
            endpoints = sorted([ #use sorting to make sure that there won't have duplicate sessions
                (ip.src, src_port),
                (ip.dst, dst_port)
            ])        
            # split packet into sessions
            session_key = f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}-{proto}"
            sessions[session_key].extend(data)
    
    return sessions #This will return a dict whose key was"src_ip:src_port-dst_ip:dst:port"


def Session_to_img(sessions):
    for key,(seesion_key, data) in enumerate(sessions.items()):
        byte_len = len(data)
        data = bytes(data)
        if byte_len > 784:
            byte_data = data[:784] #if length is longer than 784 bytes, just discard it
        else:
            byte_data = data + b'\x00' * (784 - byte_len) #if length is shorter than 784, we padding it with black
        img_data = np.array(list(byte_data), dtype=np.uint8).reshape(28, 28)
        img = Image.fromarray(img_data, 'L')  #gray scale image
    
    return img


parser = argparse.ArgumentParser()

parser.add_argument('--pcap', type=str, help='directory of your pcap file', required=True)
parser.add_argument('--output', type=str, help='output directory of converted img', default='pcap_img')
args = parser.parse_args()

def main():
    output_path = Path(args.output)
    if not os.path.exists(output_path):
        os.mkdir(output_path)
    pcap_dir = Path(args.pcap)
    try:
        for pcap in os.listdir(pcap_dir):
            print(f"file now: {pcap}")
            if not pcap.lower().endswith('.pcap'):
                print(f"Skip non-pcap file {pcap}")
                continue
            
            pcap_path = os.path.join(pcap_dir, pcap)
            sessions = SessionAll(pcap_path)
            img = Session_to_img(sessions)
            img_name = os.path.splitext(pcap)[0] + '.png'
            img_path = os.path.join(args.output, f"pcap_{img_name}")
            img.save(img_path)
            print(f"{img_name} generated!")
    except:
        print('your pcap directory is empty!')
        raise

if __name__ == "__main__":
    main()
    

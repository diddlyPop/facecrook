"""
facecrook.py
Kyle Guss & Jesse Mazzella

proof of concept
packet sniffing for pictures of faces
"""

# import

from scapy.all import *

# sniff

packets = sniff(timeout=10)

# construct PCAP file

wrpcap("packets.pcap", packets)

# search PCAP file for images

packets = rdpcap("packets.pcap")

# feed images to image classifier to determine if face





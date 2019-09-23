"""
facecrook.py
Kyle Guss & Jesse Mazzella

proof of concept
packet sniffing for pictures of faces
"""

from scapy.all import *
import zlib, scipy, numpy, re

def get_http_headers(g_http_payload):
    try:
        g_headers_raw = g_http_payload[:g_http_payload.index("\\r\\n\\r\\n")+4]
        print("passes raw state: " + g_headers_raw)
        g_headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\\r\\n", g_headers_raw))
        print("g_header: " + g_headers.keys())
    except:
        print("raw with error: " + g_http_payload)
        return None
    if 'Content-Type' not in g_headers:
        return None
    return g_headers


def extract_image(headers, http_payload):
    print("Extract image activated")
    image = None
    image_type = None
    try:
        if 'image' in headers['Content-Type']:
            image_type = headers['Content-Type'].split('/')[1]
            image = http_payload[http_payload.index('\r\n\r\n')+4:]
            try:
                if 'Content-Encoding' in headers.keys():
                    if headers['Content-Encoding'] == 'gzip':
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == 'deflate':
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None, None
    return image, image_type

# import


# sniff

packets = sniff(timeout=15)

# construct PCAP file

wrpcap("packets.pcap", packets)

# search PCAP file for images

packets = rdpcap("packets.pcap")

sessions = packets.sessions()



for session in sessions:
    http_payload = ""
    for packet in sessions[session]:
        try:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                http_payload += str(packet[TCP].payload)
        except:
            pass
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        image, image_type = extract_image(headers, http_payload)
        if image is not None and image_type is not None:
            print("FOUND IMAGE")

# feed images to image classifier to determine if face




'''
I need a regex pattern to pull matches such as:

Vary: Accept-Encoding\r\n
Connection: Upgrade, Keep-Alive\r\n
Server: Apache\r\n

from the test sample:

"b'HTTP/1.1 200 OK\r\nDate: Mon, 23 Sep 2019 08:25:40 GMT\r\nServer: Apache\r\nUpgrade: h2\r\nConnection: Upgrade, Keep-Alive\r\nVary: Accept-Encoding\r\nContent-Encoding: gzip\r\nContent-Length: 3578\r\nKeep-Alive: timeout=2, max=100\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n\x1f\x8b\x08\x00\x00\x00\x00\x00\x00"

and my current pattern:

(?P<name>.*?):(?P<value>.*?)\r\n

doesnt seem to work


'''
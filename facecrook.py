"""
facecrook.py
Kyle Guss & Jesse Mazzella

proof of concept
packet sniffing for pictures of faces
"""

from scapy.all import *
import zlib, scipy, numpy, os, re


def get_http_headers(g_http_payload):
    try:
        g_headers_raw = g_http_payload[g_http_payload.index(b"HTTP/1.1"):g_http_payload.index(b"\r\n\r\n") + 2]
        g_headers_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", g_headers_raw.decode("utf8")))
    except Exception as e:
        return None
    if 'Content-Type' not in g_headers_parsed.keys():
        return None
    return g_headers_parsed


def extract_image(headers, http_payload):
    image = None
    image_type = None
    try:
        if 'image' in headers['Content-Type']:
            image_type = headers['Content-Type'].split('/')[1]
            image = http_payload[http_payload.index(b"\r\n\r\n")+4:]
            try:
                if 'Content-Encoding' in headers.keys():
                    if headers['Content-Encoding'] == 'gzip':
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == 'deflate':
                        image = zlib.decompress(image)
            except Exception as e:
                print(e)
    except Exception as e:
        print(e)
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

carved_images = 0

PIC_DIR = f"{os.environ['USERPROFILE']}/Desktop/Facecrook/Pictures" # pic output path

for session in sessions:
    http_payload = b''
    for packet in sessions[session]:
        try:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                http_payload += bytes(packet[TCP].payload)
        except Exception as e:
            pass
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        image, image_type = extract_image(headers, http_payload)
        if image is not None and image_type is not None:
            print("FOUND IMAGE")
            file_name = '{0}-pic-{1}.{2}'.format("packets", carved_images, image_type)
            fd = open('%s/%s' % (PIC_DIR, file_name), 'wb')
            fd.write(image)
            fd.close()
            carved_images += 1


# feed images to image classifier to determine if face

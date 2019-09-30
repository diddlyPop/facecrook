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
        if g_headers_raw is not None:
            print("raw: " + g_headers_raw)
        g_headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\\r\\n", g_headers_raw))
        print("headders: " + str(g_headers.keys()))
    except Exception as e:
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
            image = http_payload[http_payload.index('\\r\\n\\r\\n')+8:]
            print("image: " + image)
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

carved_images = 0

PIC_DIR = "C:\\Users\\USER\\Desktop\\facecrook\\pictures"  # change to your windows user folder

for session in sessions:
    http_payload = ''
    for packet in sessions[session]:
        try:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                http_payload += str(packet[TCP].payload)
        except Exception as e:
            pass
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        image, image_type = extract_image(headers, http_payload)
        if image is not None and image_type is not None:
            print("FOUND IMAGE")
            file_name = '%s-pic_carver_%d.%s' % ("packets", carved_images, image_type)
            fd = open('%s/%s' % (PIC_DIR, file_name), 'wb')
            fd.write(image[2:].encode())
            fd.close()
            carved_images += 1


# feed images to image classifier to determine if face

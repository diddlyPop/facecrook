"""
facecrook.py
Kyle Guss & Jesse Mazzella

proof of concept
packet sniffing for pictures of faces
"""

from scapy.all import *
import zlib, scipy, numpy, os, re


class Sniffrr():

    def __init__(self, seconds=15):
        self.images_found = 0
        self.sniff_time = seconds
        self.packets = None
        self.directory = f"{os.environ['USERPROFILE']}/Desktop/SniffOutput"  # pic output path

    def __str__(self):
        return "Images_Found: {}, Seconds_Queued: {}".format(self.images_found, self.sniff_time)

    def AddSniff(self):
        self.sniff_time += 15

    def TakeSniff(self):
        if self.sniff_time == 0:
            if self.packets is None:
                print("No sniff time queued. No Packets stored yet.")
            else:
                print("No sniff time queued. Packets already stored though.")
        else:
            self.packets = sniff(timeout=self.sniff_time)
            self.sniff_time = 0

    def CheckSniff(self):
        '''

        :return:
        '''
        sessions = self.packets.sessions()

        for session in sessions:
            http_payload = b''
            for packet in sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        http_payload += bytes(packet[TCP].payload)
                except:
                    pass
                headers = self.get_http_headers(http_payload)
                if headers is None:
                    continue
                image, image_type = self.extract_image(headers, http_payload)
                if image is not None and image_type is not None:
                    file_name = '{0}-pic-{1}.{2}'.format("packets", self.images_found, image_type)
                    file = open('%s/%s' % (self.directory, file_name), 'wb')
                    file.write(image)
                    file.close()
                    self.images_found += 1

    def get_http_headers(self, payload_bytes):
        '''
        finds and puts http headers into dictionary
        :param payload_bytes: bytes
        :return: dictionary of headers
        '''
        try:
            headers_bytes_raw = payload_bytes[payload_bytes.index(b"HTTP/1.1"):payload_bytes.index(b"\r\n\r\n") + 2]
            headers_bytes_parsed = dict(
                re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_bytes_raw.decode("utf8")))
        except Exception as e:
            return None
        if 'Content-Type' not in headers_bytes_parsed.keys():
            return None
        return headers_bytes_parsed

    def extract_image(self, headers, payload_bytes):
        '''
        :param headers: dictionary of headers
        :param payload_bytes: corresponding bytes for these headers
        :return: tuple of image and the image type
        '''
        image = None
        image_type = None
        try:
            if 'image' in headers['Content-Type']:
                image_type = headers['Content-Type'].split('/')[1]
                image = payload_bytes[payload_bytes.index(b"\r\n\r\n") + 4:]
                try:
                    if 'Content-Encoding' in headers.keys():
                        if headers['Content-Encoding'] == 'gzip':
                            image = zlib.decompress(image, 16 + zlib.MAX_WBITS)
                        elif headers['Content-Encoding'] == 'deflate':
                            image = zlib.decompress(image)
                except:
                    pass
        except:
            pass
            return None, None
        return image, image_type


if __name__ == "__main__":
    S = Sniffrr()
    S.TakeSniff()
    S.CheckSniff()
    print(S)

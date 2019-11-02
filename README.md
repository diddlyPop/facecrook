# facecrook
gonna sniff ur face

(packet sniffing for pictures of faces)

requires python3, scapy, npcap/winpcap/libpcap

____________________________________________

import scapy & npcap on your machine

- make sure to run as admin for scapy to sniff (often gives interface error in PyCharm if not running as admin)

- run in python shell:
    ``` 
        from scapy.all import *
        get_if_list()
    ```
    should display available interfaces pulled from npcap/winpcap/libpcap
    
_____________________________________________

starting to change facecrook into a sniffing module called sniffrr, is a more OOP approach.

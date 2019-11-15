# facecrook
gonna sniff ur face

(packet sniffing for pictures of faces)

requires python3, scapy, npcap/winpcap/libpcap

opencv-python currently not available on python 3.8
____________________________________________

currently:
- collects byte data while sniffing port 80 (http traffic)
- searches byte data for headers and content (specifically images)
- parses byte data into images if present
- writes images to output folder

hope to add:
- other port sniffing options (like port for email credentials)
- send images found to image classifier trained for facial recognition
- send images found to image classifiers and print information found (whats in the pictures)
- make more object oriented for use in other modules

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

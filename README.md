# wireshark_additional
This program is working with pcap-files. Using Wireshark I'd created some pcaps to use. Wireshark intercepts tcp- and udp- packets when we're doing something online and saves all information to pcap-file. In the same time a lot of online processes are going on, and they have different source, destination, ports and protocols. Thus we can filter pcap-data by these parametrs - this is called "sessions".
# functions
Imagine situation: you have really big pcap-file and you need to split it by sessions. Moreover, it woulde be great to have list of sessions. My program is designed to this too.
# important
I added npcap-library to my program for interaction with pcap-files (you can find it hear https://npcap.com/#download). For testing you can use 44.pcap or 55.pcap.

# snifftool-detecting-SYN-Flood-Attack

// credit 1: https://github.com/kdszyubin/minisniff
// credit 2: https://elf11.github.io/2017/01/22/libpcap-in-C.html

This work generates a warning whenever SYN packets to SYN/ACK packets ratio gets greater than 3 for a particula IP pair and records the packet for further analysis.


demo video: https://youtu.be/1JHEgfujSsc

Binary generated for 64-bit ubuntu 16.04 machine

==============
How to compile
==============
run the following command:
~$ make

NOTE: set PCAP library path appropriates in case you receive and error during compilation

===========
How to run?
===========
~$ ./minisniff <packet-number> <your-pcap-file>

packet-number = 0 , for selecting all packets


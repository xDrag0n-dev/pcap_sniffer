IMPORTANT:
  - This program requires SUDO privileges to be run
  - To compile this source code you will need to install "libpcap0.8-dev".
  - This software is in beta stage, so it may contain a few programming errors.
  - Any help & feedback is greatly appreciated.
  - This software is under GPL3.0 license and open-source.

INSTALLATION:
  - The source code must be compiled with gcc/clang (or any other compiler)
  - You must have "libpcap0.8-dev" installed:
  --> sudo apt install libpcap0.8-dev
  - Then enjoy the sniffer (with a lot of colors!)

USAGE:
  - sudo ./pcap_sniffer --help:
  -  -i <interface>: interface on which to sniff
  -  -p <protocol>: protocol to sniff
  -  -s <source port>: source port to filter
  -  -d <dest. port>: destination port to filter
  -  -S <source IP>: source IP to filter
  -  -D <dest. IP>: destination IP to filter  -r <port range>: port range (from x-y)
  -  -l: list all network interfaces
  -  -n <# of packets>: number of packet to sniff (10 by default)
  -  --help: displays this menu

EXAMPLES:
  - "sudo ./pcap_sniffer -i wlan0 -n 100"         --> sniffs for 100 packets on interface "wlan0"
  - "sudo ./pcap_sniffer -i wlan0 -n 100 -p tcp"  --> sniffs for 100 TCP packets on interface "wlan0"

SCREENSHOTS:

![Screenshot from 2024-08-04 22-01-58](https://github.com/user-attachments/assets/56820d4f-968b-4de5-9dc6-a9c2275fe5f0)

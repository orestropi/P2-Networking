# P2-Networking

Project Descriptions:

Final for P2:

Parsing of tcpdump data!

How to run:
![image](https://user-images.githubusercontent.com/73619173/142068189-706efe53-60f7-4aeb-b766-54bc7a113a58.png)
run make all, in terminal at project fie location

then run ./wireview <Paramater 1: should be 1 of the four pcap files>

Program output: prints out a timestamp, then a the information for every packet, then hello world, then total packets, and total packet capture time

running make clean, will delete all executable files

Also FYI there is a limit of 10000 packets that the pogram can process

Any Questions?
Contact me on any of these ->
Discord: Orest#5659
Snapchat: orestropi
Email: oropi@wpi.edu

More Details:

1. Packet Capture Initialization:
   - The program uses the pcap library to capture network packets.
   - It opens an offline capture file specified as a command-line argument (e.g., tcpdump data file).

2. Packet Parsing:
   - The code includes a callback function (`my_callback`) that is called for each packet captured.
   - Ethernet frames are parsed to extract source and destination MAC addresses.
   - IP packets are parsed to extract source and destination IP addresses.
   - UDP packets are further analyzed to extract source and destination port numbers.
   - ARP packets are parsed to extract MAC and IP addresses of senders and targets.

3. Unique Identifiers:
   - The program maintains sets (unordered_set) for unique identifiers such as unique source and destination MAC addresses, IP addresses, UDP ports, ARP MAC addresses, and ARP IP addresses.
   - These sets are then used to calculate the number of unique identifiers and print them.

4. Timestamps:
   - The program calculates the duration of the packet capture by comparing the timestamps of the first and last packets.

5. Output:
   - The program prints the total number of processed packets.
   - It prints the count and unique identifiers for Ethernet sources, destinations, IP sources, IP destinations, UDP source and destination ports, ARP MAC sources, ARP MAC destinations, ARP IP sources, and ARP IP destinations.

6. Miscellaneous:
   - The code includes some commented-out sections, indicating possible experimentation or alternative implementations.
   - There are references to specific Linux kernel headers and structures used in packet parsing.

7. Usage:
   - The program expects the path to a tcpdump data file as a command-line argument.

8. Limitations:
   - The code has a fixed loop count of 10,000 packets, which is a limitation for larger captures.

9. External Dependencies:
   - The program relies on the pcap library for capturing and processing network packets.


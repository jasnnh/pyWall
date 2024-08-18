# pyWall
A firewall coded in Python with security measures such as IP &amp; Port block and Anti SYN Flood &amp; DDOS protection. pyWall uses pyDivert to divert/drop packets.


How it works:


the idea of a SYN Flood and DDOS attack is a barrage/spam of packets and to prevent this we would do a packet count from the source address (IP) and after x amount of packets we can choose to temporarily/permenant ban the IP or drop the packets for x seconds/minutes. With pyDivert we can block connections via Port & IP as well as block ICMP packets.

 

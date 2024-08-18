# pyWall
A firewall coded in Python with security measures such as IP &amp; Port block and Anti SYN Flood &amp; DDOS protection. pyWall uses pyDivert to divert/drop packets.


How it works:


the idea of a SYN Flood and DDOS attack is a barrage/spam of packets and to prevent this we would do a packet count from the source address (IP) and after x amount of packets we can choose to temporarily/permenant ban the IP or drop the packets for x seconds/minutes. With pyDivert we can block connections via Port & IP as well as block ICMP packets. All data will be logged for the user/security analyst to review for potential threats and issues/alerts so that if an attack does occur we have the information on it and block it in the future.

In this example I blocked port 80 (HTTP) for incoming connections and IP 127.0.0.1

![image](https://github.com/jasnnh/pyWall/blob/main/image.png)


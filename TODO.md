FEATURES:
0. Add Clean function
1. Add Tripwire check or sha1 checksum check for bin & conf
2. Add Tarpit
3. Add Fail2ban
4. Add mac rules (arptables -A INPUT -m mac --mac-source $mac -p tcp --dport ssh -j SSH_ACCEPT)
5. Add backup with git
6. Add specific mac vendor class find and drop/tarpit
7. Configure iptables start in network config instead of init.d script -or- be more init.d
8. maybe move to python script instead of bash script...
9. maybe use shorewall instead
10. use arp-scan to detect then authorize admin IP address
11. Check why ip6tables is not working on RPi 


Reminders
iface eth0 inet dhcp
        pre-up iptables-restore < /etc/iptables.conf ; ip6tables-restore < /etc/ip6tables.conf
        

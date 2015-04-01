##### Script for iptables rules construction #####
##### will check binaries presence #####

0. Two Versions:
	endpointIptables_Builder.bash -> Linux server, desktop not in frontend of the Internet
		* Works on Debian
		* Works on Raspbian (but I had to comment all ip6tables action, dunno why... at this time)
	intermediateIptables_Builder.bash -> Firewall between the Internet and Server(s), ... (To Be Done)
	
You must configure IS_HOME, IS_VM, DEBUG and , of course, Management IP addresses :-P Otherwise, you'll cut your sockets down
I left some warning before allowing you to "download-and-run" without check what i did...


#!/bin/bash
#
# Less Simple Endpoint Firewall configuration Builder.
#
# Author: Nicolargo
# Updater: onemoretime
#
# description: Activates/Deactivates the firewall at boot time
# 			   Default policy is DROP
#			   Log what is unknown
#			   Drop what is known as evil
#			   Accept a few one in INPUT
#			   Allow known in OUTPUT
#			   Tips:
#			   1. you may check with ip6tables -nvL and iptables -nvL (display NIC/rules)
#

# Script Config
DEBUG=0	 # will be less verbose (log and console)
#DEBUG=1  # Will be more verbose (log and console)
IS_VM=0	# if we are in a VM on a worstation
NETWORK_VM="192.168.1.0/24"		# NETWORK provided to/by VMs

echo -e $red"You should configure the script before doing what you're doing..."$end && exit 0

# Network config
IN="eth0"	# good side

#### INPUT ####
# Services that this system will offer to the inner network
INPUT_SSH_PORT=""
INPUT_SSH_IP=""			# Authorized IP for SSH (git, cmdline, ...) connections attempt
## TCP services
INPUT_TCP_WEB_SERVICES="443"
INPUT_TCP_WEB_IP=""	# IP allowed to initiate WEB connection. You may add 0/0 for everyone
## UDP services
INPUT_UDP_SERVICES=""	
INPUT_UDP_IP=""	# IP allowed to initiate TCP connection

### OUTPUT ###
# Services the system will use from the inner network
OUTPUT_TCP_SERVICES="22 80 123 443" # ssh, web browsing, updates downloads
OUTPUT_UDP_SERVICES="67 53 123" # DNS, NTP. For large DNS request, you must authorize TCP/53.
DNS_IP="8.8.8.8"
OUTPUT_UDP_DHCP_PORT_SRC=""
OUTPUT_UDP_DHCP_PORT_DST=""
OUTPUT_UDP_DHCP_IP=""


# Services which are allowed from outside to inner

#### Admin part ####
# Network that will be used for remote mgmt
# (if undefined, no rules will be setup)
# NETWORK_MGMT=192.168.0.0/24
# NETWORK_MGMT="192.168.1.2/32"
echo -e $red"You should add your IP before doing what you're doing..."$end && exit 0
TCP_SERVICE_MGMT_SSH="22"

# Local log
FACILITY="local7"


red="\e[31m"
green="\e[32m"
end="\e[00m"

# Remote log
REMOTE_LOG_ENABLED=0
REMOTE_LOG_IP=""
REMOTE_LOG_TCP_PORT=514
REMOTE_LOG_UDP_PORT=514
IPT_LOG_PATTERN_HEADER="[iptables : "
IPT_LOG_PATTERN_TRAILER=" ]"

# Binaries absolute location tests
IPT="/sbin/iptables"
IPT6="/sbin/ip6tables"
LOG="/usr/bin/logger"
MODPROBE="/sbin/modprobe"
CONNTRACK="/usr/sbin/conntrack"
BINARIES="$IPT $IPT6 $LOG $MODPROBE $CONNTRACK"

logging() {
	# $1: message to log/echo
	# $2: severity
	if [ $DEBUG -eq 1 ] && [[ $2 == "debug" ]] ; then
		echo $1
		$LOG -t "IptablesBuilder" -p $FACILITY.$2 $IPT_LOG_PATTERN_HEADER$1$IPT_LOG_PATTERN_TRAILER
	else
		$LOG -t "IptablesBuilder" -p $FACILITY.$2 $IPT_LOG_PATTERN_HEADER$1$IPT_LOG_PATTERN_TRAILER
	fi
}

FILE_MISSING=""
for bin in ${BINARIES} ; do 
	if ! [ -x $bin ] ; then
		FILE_MISSING="$FILE_MISSING $bin"
	fi
done
if [ ! $FILE_MISSING == "" ] ; then
	echo -e $red"Following file is missing: $FILE_MISSING"$end
	exit 1
fi

# install modules dependencies
$MODPROBE ip_tables
$MODPROBE ip_conntrack

set_kernel () {
	echo -e $green"Setting kernel Flags"$end
	# KERNEL PARAMETER CONFIGURATION
	# (some will only work with some kernel versions)
	# ????
	echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

	# PREVENT YOU SYSTEM FROM ANSWERING ICMP ECHO REQUESTS
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
	
	# DROP ICMP ECHO-REQUEST MESSAGES SENT TO BROADCAST OR MULTICAST ADDRESSES
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
	
	# DONT ACCEPT ICMP REDIRECT MESSAGES
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
	
	# DONT SEND ICMP REDIRECT MESSAGES
	echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
	
	# DROP SOURCE ROUTED PACKETS
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
	
	# ENABLE TCP SYN COOKIE PROTECTION FROM SYN FLOODS
	echo 1 > /proc/sys/net/ipv4/tcp_syncookies
	
	# ENABLE SOURCE ADDRESS SPOOFING PROTECTION
	echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
	
	# LOG PACKETS WITH IMPOSSIBLE ADDRESSES (DUE TO WRONG ROUTES) ON YOUR NETWORK
	echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
	
	# DISABLE IPV4 FORWARDING
	echo 0 > /proc/sys/net/ipv4/ip_forward
	
	echo -e $red"Are you sure the kernel is correctly configured..."$end && exit 0
}


##########################
# Start the Firewall rules
##########################
fw_start () {
	set_kernel

	# Clearing old rules and counters
	echo -e $green"Clearing Rules and Counters"$end
	# Set default policies
	## IPv4
	$IPT -P OUTPUT DROP
	$IPT -P INPUT DROP
	$IPT -P FORWARD DROP

	## IPv6
	$IPT6 -P OUTPUT DROP
	$IPT6 -P INPUT DROP
	$IPT6 -P FORWARD DROP	

	# Flush rules
	## IPv4
	$IPT -F OUTPUT
	$IPT -F INPUT
	$IPT -F FORWARD

	## IPv6
	$IPT6 -F OUTPUT
	$IPT6 -F INPUT
	$IPT6 -F FORWARD	

	
	# New chains
	echo -e $green"Setting New rules"$end
	## Chain SSH_DROP: LOG&DROP SSH Abuse
	$IPT -N SSH_DROP
	$IPT -A SSH_DROP -m limit --limit 1/s -j LOG --log-prefix '[SSH_ATTACK]: '
	$IPT -A SSH_DROP -j DROP
	## Chain SSH_ACCEPT: LOG&ACCEPT SSH Admin connection
	$IPT -N SSH_ACCEPT
	$IPT -A SSH_ACCEPT -m limit --limit 1/s -j LOG --log-prefix '[SSH_ADMIN]: '
	$IPT -A SSH_ACCEPT -j ACCEPT
	## Chain LOG_DROP: LOG&DROP unknown attempt
	$IPT -N LOG_DROP
	$IPT -A LOG_DROP -m limit --limit 1/s -j LOG --log-prefix '[LOG_DROP]: '
	$IPT -A LOG_DROP -j DROP
	## Chain LOG_DROP for IPv6: LOG&DROP unknown attempt
	$IPT6 -N LOG_DROP
	$IPT6 -A LOG_DROP -m limit --limit 1/s -j LOG --log-prefix '[LOG_DROP]: '
	$IPT6 -A LOG_DROP -j DROP	
	
	## Zeroising counters
	$IPT -Z
	$IPT6 -Z
	
	##########################
	# INPUT
	##########################
	echo -e $green"Setting INPUT Rules"$end
	## We'll start by dropping all known kind of forged pkts	
	### DROP INVALID
	$IPT -A INPUT -m state --state INVALID -j DROP
	
	### DROP INVALID IP PACKETS
	$IPT -A INPUT -i $INT -s 10.0.0.0/8 -j DROP
	$IPT -A INPUT -i $INT -s 172.16.0.0/16 -j DROP
	if [ $IS_VM -eq 0 ] ; then
		$IPT -A INPUT -i $INT -s 192.168.0.0/24 -j DROP
	fi
	$IPT -A INPUT -i $INT -s 127.0.0.0/8 -j DROP

	### DROP INVALID SYN PACKETS
	$IPT -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
	$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
	$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

	### MAKE SURE NEW INCOMING TCP CONNECTIONS ARE SYN PACKETS; OTHERWISE WE NEED TO DROP THEM 
	$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

	### DROP PACKETS WITH INCOMING FRAGMENTS. THIS ATTACK RESULT INTO LINUX SERVER PANIC SUCH DATA LOSS
	$IPT -A INPUT -f -j DROP

	### DROP INCOMING MALFORMED XMAS PACKETS.
	### While this is clearly a scan, LOG&DROP
	$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROP

	### DROP INCOMING MALFORMED NULL PACKETS
	### While this is clearly a scan, LOG&DROP
	$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROP


	# Accept Related TCP/UDP/ICMP traffic:
	$IPT -A INPUT -p tcp -i $INT -m state --state ESTABLISHED,RELATED -j ACCEPT
	$IPT -A INPUT -p udp -i $INT -m state --state ESTABLISHED,RELATED -j ACCEPT
	$IPT -A INPUT -p icmp -i $INT -m state --state ESTABLISHED,RELATED -j ACCEPT

	# Let's start to ACCEPT New incoming & well-known traffic
	## Input - Services
	echo -e $green"Setting Users INPUT Rules"$end
	if [ -n "$INPUT_TCP_SERVICES" ] ; then
		for PORT in $INPUT_TCP_SERVICES; do
			$IPT -A INPUT -p tcp --dport ${PORT} -j ACCEPT
		done
	fi
	if [ -n "$INPUT_UDP_SERVICES" ] ; then
		for PORT in $INPUT_UDP_SERVICES; do
			$IPT -A INPUT -p udp --dport ${PORT} -j ACCEPT
		done
	fi

	## ADMIN RULES
	echo -e $green"Setting ADMIN INPUT Rules"$end
	### SSH Access
	$IPT -A INPUT -i $INT -p tcp --dport ${TCP_SERVICE_MGMT_SSH} -m recent --update --seconds 60 --hitcount 4 --name SSH -j SSH_DROP
	$IPT -A INPUT -i $INT -p tcp --dport ${TCP_SERVICE_MGMT_SSH} -m recent --set --name SSH
	if [ -n "$NETWORK_MGMT" ] ; then
		$IPT -A INPUT -i $INT -p tcp --src ${NETWORK_MGMT} --dport ${TCP_SERVICE_MGMT_SSH} -j SSH_ACCEPT
	fi
	
	### Remote testing for Admin
	$IPT -A INPUT --src ${NETWORK_MGMT} -p icmp -m state --state NEW -j ACCEPT
	
	## Final Input Rules
	echo -e $green"Setting Last INPUT Rules"$end
	$IPT -A INPUT -i $INT -p tcp --dport ${TCP_SERVICE_MGMT_SSH} -m state --state NEW -j LOG_DROP	# Want all other ssh connection attempt logged
	$IPT -A INPUT -i lo -j ACCEPT
	$IPT -A INPUT -j LOG_DROP
	$IPT6 -A INPUT -j LOG_DROP
	
	##########################
	# OUTPUT
	##########################
	echo -e $green"Setting OUTPUT Rules"$end	
	## DROP INVALID because we are not hostile
	$IPT -A OUTPUT -m state --state INVALID -j DROP

	## DROP INVALID SYN PACKETS
	$IPT -A OUTPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
	$IPT -A OUTPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
	$IPT -A OUTPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

	## MAKE SURE NEW OUTGOING TCP CONNECTIONS ARE SYN PACKETS; OTHERWISE WE NEED TO DROP THEM 
	$IPT -A OUTPUT -p tcp ! --syn -m state --state NEW -j DROP

	## DROP PACKETS WITH OUTGOING FRAGMENTS. THIS ATTACK RESULT INTO LINUX SERVER PANIC SUCH DATA LOSS
	$IPT -A OUTPUT -f -j DROP

	## DROP OUTGOING MALFORMED XMAS PACKETS
	$IPT -A OUTPUT -p tcp --tcp-flags ALL ALL -j DROP
	
	## DROP OUTGOING MALFORMED NULL PACKETS
	$IPT -A OUTPUT -p tcp --tcp-flags ALL NONE -j DROP
		
	# Allow previously initiated traffic
	$IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	
	# ICMP is permitted:
	$IPT -A OUTPUT -p icmp -m state --state NEW -j ACCEPT
	
	# So are security package updates:
	# Note: You can hardcode the IP address here to prevent DNS spoofing
	# and to setup the rules even if DNS does not work but then you
	# will not "see" IP changes for this service:
	$IPT -A OUTPUT -p tcp -d security.debian.org --dport 80 -j ACCEPT
	# As well as the services we have defined:
	if [ -n "$OUTPUT_TCP_SERVICES" ] ; then
		for PORT in $OUTPUT_TCP_SERVICES; do
			$IPT -A OUTPUT -p tcp --dport ${PORT} -j ACCEPT
		done
	fi
	if [ -n "$OUTPUT_UDP_SERVICES" ] ; then
		for PORT in $OUTPUT_UDP_SERVICES; do
			$IPT -A OUTPUT -p udp --dport ${PORT} -j ACCEPT
		done
	fi
	if [ -n "$OUTPUT_UDP_DHCP_IP" ] ; then
		$IPT -A OUTPUT -o $INT --dst ${OUTPUT_UDP_DHCP_IP} -p udp --dport ${OUTPUT_UDP_DHCP_PORT_DST} -j ACCEPT
	fi
	echo -e $green"Setting Last OUTPUT Rules"$end
	$IPT -A OUTPUT -o lo -j ACCEPT
	
	# All other connections are registered in syslog
	$IPT -A OUTPUT -j LOG_DROP
	$IPT6 -A OUTPUT -j LOG_DROP
	
	##########################
	# FORWARD
	##########################
	# As we are on an endpoint firewall, we shouldn't have FORWARD traffic
	# Anyway, most of decent and recent server come with two or more NIC
	# So... just in case
	echo -e $green"Setting FORWARD Rules"$end
	$IPT -A FORWARD -j LOG_DROP
	$IPT6 -A FORWARD -j LOG_DROP

}
##########################
# Stop the Firewall rules
##########################
fw_stop () {
	CUSTOM_CHAIN_TO_DELETE=""
	$IPT -C SSH_ACCEPT -j ACCEPT
	if [ $? -eq 0 ] ; then
		CUSTOM_CHAIN_TO_DELETE=$CUSTOM_CHAIN_TO_DELETE + "$CUSTOM_CHAIN_TO_DELETE SSH_ACCEPT"
	fi
	$IPT -C SSH_DROP -j DROP
	if [ $? -eq 0 ] ; then
		CUSTOM_CHAIN_TO_DELETE=$CUSTOM_CHAIN_TO_DELETE + "$CUSTOM_CHAIN_TO_DELETE SSH_DROP"
	fi
	$IPT -C LOG_DROP -j DROP
	if [ $? -eq 0 ] ; then
		CUSTOM_CHAIN_TO_DELETE=$CUSTOM_CHAIN_TO_DELETE + "$CUSTOM_CHAIN_TO_DELETE LOG_DROP"
	fi
	$IPT -F
	if [ -n "$CUSTOM_CHAIN_TO_DELETE" ] ; then
		for chain in ${CUSTOM_CHAIN_TO_DELETE} ; do
			$IPT -X $chain
		done
	fi
	$IPT -t nat -F
	$IPT -t mangle -F	
	$IPT -Z
	$IPT -P INPUT DROP
	$IPT -P FORWARD DROP
	$IPT -P OUTPUT ACCEPT

	
	$IPT6 -C LOG_DROP -j DROP
	if [ $? -eq 0 ] ; then
		$IPT6 -F
		$IPT6 -X LOG_DROP
	else 
		$IPT6 -F
	fi	
	$IPT6 -Z
	$IPT6 -P INPUT DROP
	$IPT6 -P FORWARD DROP
	$IPT6 -P OUTPUT ACCEPT	
}
##########################
# Clear the Firewall rules
##########################
fw_clear () {
	fw_stop
	$IPT -P INPUT ACCEPT
	$IPT -P FORWARD ACCEPT
	$IPT -P OUTPUT ACCEPT
	$IPT6 -P INPUT ACCEPT
	$IPT6 -P FORWARD ACCEPT
	$IPT6 -P OUTPUT ACCEPT	
}
############################
# Restart the Firewall rules
############################
fw_restart () {
	echo -e $green"Stopping firewall..."$end
	fw_stop
	echo -e $green"Starting firewall..."$end
	fw_start
}

############################
# Installing the Firewall rules
############################
fw_install () {
	echo -e $red"Are you sure you test enough before installation..."$end && exit 0
	fw_save
	# create iptables init.d script.
	# -----------------------------------------------------------
(
cat <<'EOF'
#!/bin/bash
#
# Less Simple EndPoint Firewall configuration.
#
# Author: Nicolargo
# Updater: onemoretime
#
# chkconfig: 2345 9 91
# description: Activates/Deactivates the firewall at boot time
# 			   Default policy is DROP
#			   Log what is unknown
#			   Drop what is known as evil or useless
#			   Accept a few one in INPUT
#			   Allow known in OUTPUT
#			   Tips:
#			   1. you may check with ip6tables -nvL and iptables -nvL
#
### BEGIN INIT INFO
# Provides: iptables
# Required-Start: $syslog $network
# Required-Stop: $syslog $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Start firewall daemon at boot time
# Description: Custom EndPoint Firewall rules.
### END INIT INFO

PATH=/bin:/sbin:/usr/bin:/usr/sbin
DESC="Starts iptables rules"
NAME=iptables
IPT=/sbin/iptables
IPT6=/sbin/ip6tables
SCRIPTNAME=/etc/init.d/"$NAME"

test -f $IPTABLES || exit 0
test -f $IP6TABLES || exit 0

. /lib/lsb/init-functions

fw_stop () {
	CUSTOM_CHAIN_TO_DELETE=""
	$IPT -C SSH_ACCEPT -j ACCEPT
	if [ $? -eq 0 ] ; then
		CUSTOM_CHAIN_TO_DELETE="$CUSTOM_CHAIN_TO_DELETE SSH_ACCEPT"
	fi
	$IPT -C SSH_DROP -j DROP
	if [ $? -eq 0 ] ; then
		CUSTOM_CHAIN_TO_DELETE="$CUSTOM_CHAIN_TO_DELETE SSH_DROP"
	fi
	$IPT -C LOG_DROP -j DROP
	if [ $? -eq 0 ] ; then
		CUSTOM_CHAIN_TO_DELETE="$CUSTOM_CHAIN_TO_DELETE LOG_DROP"
	fi
	$IPT -F
	if [ -n "$CUSTOM_CHAIN_TO_DELETE" ] ; then
		for chain in ${CUSTOM_CHAIN_TO_DELETE} ; do
			$IPT -X $chain
		done
	fi
	$IPT -t nat -F
	$IPT -t mangle -F	
	$IPT -Z
	$IPT -P INPUT DROP
	$IPT -P FORWARD DROP
	$IPT -P OUTPUT ACCEPT

	
	$IPT6 -C LOG_DROP -j DROP
	if [ $? -eq 0 ] ; then
		$IPT6 -F
		$IPT6 -X LOG_DROP
	else 
		$IPT6 -F
	fi	
	$IPT6 -Z
	$IPT6 -P INPUT DROP
	$IPT6 -P FORWARD DROP
	$IPT6 -P OUTPUT ACCEPT		
}

case "$1" in
	start)
		echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
		# PREVENT YOU SYSTEM FROM ANSWERING ICMP ECHO REQUESTS
		echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
		# DROP ICMP ECHO-REQUEST MESSAGES SENT TO BROADCAST OR MULTICAST ADDRESSES
		echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
		# DONT ACCEPT ICMP REDIRECT MESSAGES
		echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
		# DONT SEND ICMP REDIRECT MESSAGES
		echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
		# DROP SOURCE ROUTED PACKETS
		echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
		# ENABLE TCP SYN COOKIE PROTECTION FROM SYN FLOODS
		echo 1 > /proc/sys/net/ipv4/tcp_syncookies
		# ENABLE SOURCE ADDRESS SPOOFING PROTECTION
		echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
		# LOG PACKETS WITH IMPOSSIBLE ADDRESSES (DUE TO WRONG ROUTES) ON YOUR NETWORK
		echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
		# DISABLE IPV4 FORWARDING
		echo 0 > /proc/sys/net/ipv4/ip_forward
		
		if [ -f /etc/iptables.backup ] ; then
			echo -ne "\e[31mStarting IPv4 firewall...\e[00m\t"
			/sbin/iptables-restore < /etc/iptables.backup
			echo -e "[ \e[32mOK\e[00m ]"
		else
			echo -e "\e[31mno iptables conf found\e[00m"
		fi
		if [ -f /etc/ip6tables.backup ] ; then
			echo -ne "\e[31mStarting IPv6 firewall...\e[00m\t"
			/sbin/ip6tables-restore < /etc/ip6tables.backup
			echo -e "[ \e[32mOK\e[00m ]"
		else
			echo -e \e[31m"no ip6tables conf found"\e[00m
		fi		
		;;
	stop)
		echo -ne "\e[31mStopping firewall...\e[00m"
		fw_stop
		echo -e "[ \e[32mOK$end\e[00m ]"
		;;
	restart)
		$0 stop
		$0 start
		;;
	*)
		echo -e "\e[31mUsage: $0 {start|stop|restart}\e[00m"
		exit 1
		;;
esac
exit 0
EOF
) > /etc/init.d/iptables
	# -----------------------------------------------------------
	# installing files
	chmod 755 /etc/init.d/iptables
	chown root:root /etc/init.d/iptables
	update-rc.d iptables defaults 
}

##########################
# Save the Firewall rules
##########################
fw_save () {
	if [ -f /etc/iptables.backup ] ; then
		chmod u+w /etc/iptables.backup
	fi
	$IPT-save > /etc/iptables.backup
	chmod 440 /etc/iptables.backup
	chown root:root /etc/iptables.backup
	if [ -f /etc/ip6tables.backup ] ; then
		chmod u+w /etc/ip6tables.backup
	fi
	$IPT6-save > /etc/ip6tables.backup
	chmod 440 /etc/ip6tables.backup
	chown root:root /etc/ip6tables.backup	
}
##########################
# Restore the Firewall rules
##########################
fw_restore () {
	if [ -f /etc/iptables.backup ]; then
		$IPT-restore < /etc/iptables.backup
	fi
	if [ -f /etc/ip6tables.backup ]; then
		$IPT6-restore < /etc/ip6tables.backup
	fi
}
##########################
# Test the Firewall rules
##########################
fw_test () {
	fw_save
	fw_restart
	sleep 30
	fw_restore
}
case "$1" in
	start)
		fw_start
		echo -e $green"done."$end
		;;
	restart)
		fw_restart
		echo -e $green"done."$end
		;;
	stop)
		echo -e $green"Stopping firewall..."$end
		fw_stop
		echo "done."
		;;
	clear)
		echo -e $green"Clearing firewall rules..."$end
		fw_clear
		echo "done."
		;;
	install)
		echo -e $red"You should read the script before doing what you're doing..."$end && exit 0
		echo -e $green"Creating and starting firewall..."$end
		fw_start
		echo -e $green"Installing files at startup..."$end
		fw_install
		;;
	test)
		echo -en "Test Firewall rules..."
		echo -n "Previous configuration will be restore in 30 seconds"
		fw_test
		echo -n "Configuration as been restored"
		;;
	*)
		echo -e $red"Usage: $0 {start|stop|restart|clear|install|test}"$end
		echo -e $red"Be aware that stop drop all incoming/outgoing traffic !!!"$end
		echo -e $red"Be aware that clear or clean with leave without firewall rules !!!"$end
		exit 1
		;;
esac
exit 0
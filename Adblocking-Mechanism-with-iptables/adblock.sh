#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"
adblockRulesIPv6="adblockRulesIPv6"


function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi

    if [ "$1" = "-domains" ]; then
        echo "Configuring adblock rules based on the domain names and resolving them to IP addresses."
        echo "This will take 3-4 minutes..."
        while read -r line; do
            # We use 'host' to obtain the IP addresses of the domains given 
            # We use awk to filter the output of host and extract the IP addresses (printing the 4th field of the output for IPv4 and the 5th for IPv6)
            host "$line" | awk '/has address/ { print $4 }'
            host "$line" | awk '/has IPv6 address/ { print $5 }'
        done < "$domainNames" > "$IPAddresses"
        # We ensure the IPAddresses file is not empty
        if [ -s "$IPAddresses" ]; then
            # It reads the resolved IP addresses and we add the iptables rules to block traffic
            while read -r ip; do
                # We check if the address is IPv4 or IPv6
                 if [[ $ip == *":"* ]]; then
                    ip6tables -A OUTPUT -d "$ip" -j REJECT
                    ip6tables -A INPUT -s "$ip" -j REJECT
                else
                    iptables -A OUTPUT -d "$ip" -j REJECT
                    iptables -A INPUT -s "$ip" -j REJECT
                fi
                    echo "$ip"       
            done < "$IPAddresses"
            echo "Adblock rules configured based on the domain names"
            echo "Domain names have been resolved to IP addresses"
        else
            echo "Empty file. Cannot configure rules."
        fi
        true

    elif [ "$1" = "-ips" ]; then
        # We ensure the IPAddresses file is not empty
        if [ -s "$IPAddresses" ]; then
            # Read each IP address and add the iptables rules to block traffic
            while IFS= read -r ip
            do
            # We check if the address is IPv4 or IPv6
            if [[ $ip == *":"* ]]; then
                ip6tables -A OUTPUT -d "$ip" -j REJECT
                ip6tables -A INPUT -s "$ip" -j REJECT
            else
                iptables -A OUTPUT -d "$ip" -j REJECT
                iptables -A INPUT -s "$ip" -j REJECT
            fi
            done < "$IPAddresses"
            echo "Adblock rules configured based on IP addresses."
        else
            echo "Empty file. Cannot configure rules."
        fi
        true

    elif [ "$1" = "-save"  ]; then
	    echo "Saving rules..."
        #We save the output to two different adblockRules files
	    iptables-save > "$adblockRules"
        ip6tables-save > "$adblockRulesIPv6"
	    echo "Save complete!"
        true
        
    elif [ "$1" = "-load" ]; then
        echo "Loading rules..."
        # We apply IPv4 rules
        iptables-restore < "$adblockRules"
        # We apply IPv6 rules
        ip6tables-restore < "$adblockRulesIPv6"
        echo "Loading complete!"
        true

    elif [ "$1" = "-reset" ]; then
        #We flush all existing iptables rules in all chains
        iptables -F
        ip6tables -F 
        echo "Rules have been reset to default settings (accept all)."
        true
        
    elif [ "$1" = "-list" ]; then
        #We list all current iptables rules
        echo "Listing rules..."
        echo "IPv4 rules:"
        iptables -L
        echo "IPv6 rules:"
        ip6tables -L
        true  

    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' & '$adblockRulesIPv6' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' & '$adblockRulesIPv6' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0

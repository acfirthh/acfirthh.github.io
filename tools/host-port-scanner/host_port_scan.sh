#!/bin/bash

banner () {
    printf "Basic Host Scan and Port Scan Tool\nYou should enter an IP address in the range that you want to scan.\n"
    printf "For Example:\n    You want to scan the range: 192.168.1.0 - 192.168.1.254\n    Enter an IP address in that range, such as '192.168.1.35'\n    The script will do the rest for you.\n"
    printf "\nTools Required:\n    - ping\n    - nc\n"
    printf "\nThe port scan will scan the port range from 1 to 100.\nYou can change this range by modifying the values within the 'port_scan' function.\n"
    printf "\nYou can press CTRL+C at any point to halt the scan.\n\n"
}

check_ping () {
    if ! command -v ping 2>&1 >/dev/null
    then
        printf "\n[!] The Tool 'ping' Could Not Be Found...\n[!] Cannot Scan For Hosts.\n"
        exit 1
    fi
}

check_nc () {
    if ! command -v nc 2>&1 >/dev/null
    then
        printf "\n[!] The Tool 'nc' Could Not Be Found...\n[!] Cannot Scan For Open Ports.\n"
        exit 1
    fi
}

validate_ip() {
    local ip=$1
    local stat=1

    # Check if the input matches the IP address pattern
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
        # Check if each octet is between 0 and 255
        if [[ $i1 -le 255 && $i2 -le 255 && $i3 -le 255 && $i4 -le 255 ]]; then
            stat=0
        fi
    fi
    return $stat
}

host_scan () {
    ip_addr=()
	
    for i in {1..254}
    do
        host_ip=$(ping -c 1 -W 0.2 $1$i | grep "bytes from" | sed -E 's/.*from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):.*/\1/')
        if [ -n "$host_ip" ]; then
            printf "Found Host: $host_ip\n"
            ip_addr+=( $host_ip )
        fi
    done
}

port_scan () {	
    for ip in "${ip_addr[@]}"
    do
      printf "\nScanning IP: $ip\n"
      nc -zv -w 1 $ip 1-100 2>&1 | grep "succeeded"
    done
}

# Print banner
banner
# Check if ping is available
check_ping
# Get current host IP address
current_ip_addr=$(hostname -I | awk '{print $1}')
# Get IP address from user input
echo
read -p "[?] Enter Target IP Address (Your Current IP - $current_ip_addr [default]): " target_ip_addr

# Set default IP address to user's current IP, if no IP is entered
target_ip_addr=${target_ip_addr:-$current_ip_addr}

# Check if user input is a valid IP
if validate_ip "$target_ip_addr"
then
    printf "\n[*] Valid IP Address: $target_ip_addr\n\n"
else
    printf "\n[!] Invalid IP Address: $target_ip_addr\n"
    exit 1
fi

# Strip last octet from IP
stripped_ip="${target_ip_addr%.*}."

# Start host scan
printf "[*] Starting Host Scan: ${stripped_ip}0/24...\n"
host_scan $stripped_ip

# Ask if the user wants to continue with the port scan
echo
read -p "[?] Continue with port scan (Y/N): " user_response

# Check user response
case "$user_response" in
    [Yy]*)  # If user enters y or Y
        # Check if nc is available
        check_nc
        printf "\n\n[*] Starting Port Scan on All Discovered Hosts.\n[~] This Could Take a While...\n"
        # Sleep for 2 seconds
        sleep 2
        # Do port scan
        port_scan
        ;;
    [Nn]* | *)  # If user enters n or N, or anything else
        printf "\n[!] Port Scan Not Continuing.\n[!] Exiting...\n"
        exit 0
        ;;
esac

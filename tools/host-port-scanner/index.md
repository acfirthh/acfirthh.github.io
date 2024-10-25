---
title: "Basic Host and Port Scanner"
permalink: /tools/host-port-scanner
---

<h1><ins>Basic Host and Port Scanner</ins></h1>

**Author:** [acfirthh](https://github.com/acfirthh)

**Download Link:** [Host and Port Scanner](/tools/host-port-scanner/host_port_scan.sh)

## Why Did I Write This Tool?
During CTFs, I sometimes come across situations where I need to find open ports on hosts that are on the same network as the compromised target. But before I can scan for open ports, I have to find the hosts first!

Of course, it's possible to use [NMAP](https://nmap.org/) as they offer static binaries that have **ping sweep (host discovery)** and **port scanning** functionality.\
However, if the network connection to the target isn't particularly fast then it can take a while to transfer to binary to the compromised system. Not to mention, the NMAP binary would be immediately flagged by any half-decent **anti-malware** or **IDS** due to it being a known ***"hacking tool"***.

The script I have written is only 111 lines long of **Bash** scripting, including code comments, and empty lines between functions for readability.\
Removing comments and *unnecessary* empty lines gets the line count down to around **90**.

The minimality of this script allows for it to be copied and pasted into a file on the compromised target, such as using the **nano** text editor.\
Even if you have such a limited shell into the target where you cannot use any text editors like **nano** or **vim** and you can only use **`echo "file_content" > file.txt`** to create files, then you can **Base64** encode the script and then use `echo` to get the file onto the target.

##### Base64 Encoding - Script Transfer (with restricted shell):
1. Run the command: `cat host_port_scan.sh | base64 -w0`


2.  ***Copy the output***

3. Run the command: `echo "<copied Base64 output>" | base64 -d > host_port_scan.sh`

4. Make the script executable: `chmod +x host_port_scan.sh`

5. Run the script: `./host_port_scan.sh`

### Features:
This script is written entirely in **Bash**, primarily compatible with **Unix-like** Operating Systems, including:
- **Linux Distros** (like Ubuntu, CentOS, Fedora, Debian, etc.)
- **macOS** (which includes Bash by default, though newer versions use Zsh as the default shell)
- **FreeBSD** (and other BSD variants)
- **Solaris**

It also uses only two external tools, **ping** and **nc**, which are both usually installed on **Linux** distributions.\
The script automatically checks if both of these tools are installed before attempting to run the **host scan** and the **port scan**.

## host_port_scan.sh
```
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
```
You can either copy and paste the script from here, or you can download the script from [here](/tools/host-port-scanner/host_port_scan.sh) or from the download link at the top of this page.

## Expected Output
Running the script, you should expect to see output like this:
```
$ ./host_port_scan.sh
Basic Host Scan and Port Scan Tool
You should enter an IP address in the range that you want to scan.
For Example:
    You want to scan the range: 192.168.1.0 - 192.168.1.254
    Enter an IP address in that range, such as '192.168.1.35'
    The script will do the rest for you.

Tools Required:
    - ping
    - nc

The port scan will scan the port range from 1 to 100.
You can change this range by modifying the values within the 'port_scan' function.

You can press CTRL+C at any point to halt the scan.


[?] Enter Target IP Address (Your Current IP - 10.0.0.35 [default]): 

[*] Valid IP Address: 10.0.0.35

[*] Starting Host Scan: 10.0.0.0/24...
Found Host: 10.0.0.1
Found Host: 10.0.0.7
Found Host: 10.0.0.19
Found Host: 10.0.0.31
Found Host: 10.0.0.35
Found Host: 10.0.0.56

[?] Continue with port scan (Y/N): y


[*] Starting Port Scan on All Discovered Hosts.
[~] This Could Take a While...

Scanning IP: 10.0.0.1
Connection to 10.0.0.1 53 port [tcp/domain] succeeded!
Connection to 10.0.0.1 80 port [tcp/http] succeeded!

Scanning IP: 10.0.0.7
Connection to 10.0.0.7 22 port [tcp/ssh] succeeded!

Scanning IP: 10.0.0.19

Scanning IP: 10.0.0.31
Connection to 10.0.0.31 22 port [tcp/ssh] succeeded!
Connection to 10.0.0.31 25 port [tcp/smtp] succeeded!
Connection to 10.0.0.31 26 port [tcp/*] succeeded!

Scanning IP: 10.0.0.35
Connection to 10.0.0.35 80 port [tcp/http] succeeded!

Scanning IP: 10.0.0.56
Connection to 10.0.0.56 22 port [tcp/ssh] succeeded!
```

### Future Improvements
At the moment the script only allows for a user to enter an IP address, it scans the full range of IP's for that IP subnet, and then ask the user if they want to do a port scan.

I plan to allow the user to select if they want to do a port scan, then allow the user to enter a specific IP address to scan.
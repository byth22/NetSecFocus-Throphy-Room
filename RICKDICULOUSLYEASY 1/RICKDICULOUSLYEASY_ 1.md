# RICKDICULOUSLYEASY: 1

# 1 Information gathering
## 1.1 Discovery host
`nmap -n -Pn -F 192.168.196.1/24 -oN host_discovery.txt`
![91b5333d5330b9727425b49e863e2c36.png](./_resources/9cfb3f72568545c0b69eb14de99480e5.png)


## 1.2 Service enum
`nmap -sV -sC -p- 192.168.196.5 -oN full_service_enum-sC.txt`
![9aebc3d504f0a9808014d52a2cd2ecb7.png](./_resources/c36c3e0eb80f445986c9dd8e93dd8acb.png)
![d222bd9cf14f34fd70467fc038ce5e1f.png](./_resources/8ab6265ab1cb4d0782edbebf9b6d37d6.png)

`nmap -sV -sU -F  -oN udp-sC-sV.txt`

## 1.3 Web
### 1.3.1 Gobuster enum dir
`gobuster dir -u http://192.168.196.5 -w /usr/share/wordlists/dirb/big.txt -t 50 -f -o info-slash.txt`
![cdb28ad65122f6fa488892beff763e95.png](./_resources/eae415a1f1ab4ad4879b78206abd66be.png)

`gobuster dir -u http://192.168.196.5 -w /usr/share/wordlists/dirb/big.txt -t 50 -o info.tx`
![21dba988fb0b57b51f2d2742eb4e4fc1.png](./_resources/a9541b2898a7402fa3883bcc3e8e0d58.png)

### 1.3.2 Robots.txt
![4e2788048ac30ba0d346f47fe63534af.png](./_resources/744785b85b1f4c01931ef8c6da3497b0.png)

### 1.3.3 Passwords.html
![82bbc62feaad0896d14fae32f708b956.png](./_resources/50bb506641f14f4aa7dc5d8fe01fe94b.png)
![466870d6b8a8af3a8e867a8376141aab.png](./_resources/59fad14f66774cb0957986ddd0fc341c.png)
One password: winter

### 1.3.4 Tracertool
![83a413f0fb27b7dd0d621058a453a53c.png](./_resources/8402a57c562d4cd795ffe23702a1a49f.png)
![12ed8ccfae4bdba7b55dca826c4fc9be.png](./_resources/7d0cc4d178454781bd16c277038a0b01.png)
Is possible concatenate other commands with semicolon. But `cat` is blocked.
However `head` and `tail` are usable.
![a14f89664b17afeb6d17845e40a9f44b.png](./_resources/f944b08e90ad4ff69e442ca0af3cf73d.png)
Now users have been enumerated.


# 2 Exploitation
## 2.1 SSH as Summer
And with the previously enumerated Summer user combined with the password `winter`, we can login.
![559eddb5d97a6327ac0cc27bf1a82bcd.png](./_resources/3d79a7c04fe441ce964523a896fac710.png)


# 3 Post-exploitation
![bcc4a8276553a834e58a07ffc7466058.png](./_resources/dc40b5f6108d47ea8b06eb77bcceac4b.png)

The zip file needs password to be extracted:
![a330460022cafbe50f39d21435fca515.png](./_resources/adf86691bb9641e39b59602da06b3582.png)

And in the file `Safe_Password.jpg`, using `strings` command to get all possible strings, there is a possible password:
![18c872938af4eda9d30f243e15266c94.png](./_resources/865f05d28d164201af8189b62ee19439.png)

Here's another password (131333):
![55a5f148ea1f459d22c39e191835f92d.png](./_resources/69d3e93d5a5b4db68969a8a366d2d50c.png)

We can use in the safe file binary:
![59a50e28b66bfed5b58df5c1082b324b.png](./_resources/9f8e0aae5d24498aa47031247ebc62e4.png)

https://rickandmorty.fandom.com/wiki/Rick_Sanchez
![f72f3ac2449d8c2c1122402aad3badd0.png](./_resources/073d8a2fbff34b5e862f83123abcf552.png)

## 3.1 Crunch to generate wordlist
Following this tips:
- 1 upper
- 1 digit
- one of the following words (the flesh curtains)

`crunch 5 5 -t ,%The >> wordlist.txt`
`crunch 7 7 -t ,%Flesh >> wordlist.txt`
`crunch 10 10 -t ,%Curtains >> wordlist.txt`

## 3.2 Brute-force ssh with Hydra
`hydra -l RickSanchez -P wordlist.txt 192.168.196.4 ssh -s 22222 -I`
![301dd38c5cc8952fb42d4f099d21969c.png](./_resources/37b422f7806248fc8f808bbceec68cc9.png)
RickSanchez:P7Curtains

## 3.3 Su command as RickSanchez
![ff671c7ce43585582bb5a00f6850b004.png](./_resources/1fef25ab4762460facd7c8d46046621e.png)


## 3.4 Root usind sudo permission
![f69ca5f924622544018b96db8198221a.png](./_resources/0502953e0fe74c238b9da3a1a1a12b7c.png)
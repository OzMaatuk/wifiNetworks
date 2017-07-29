
# wifiNetworks
final project - wifi networks - karma attack + prob attack + fake ap

fixing and combaining attacks from couple of sources,


# first Part
using scapy-fakeap by rpp0 github
https://github.com/rpp0/scapy-fakeap
and Wireless "Deauth" Attack by Jordan
http://raidersec.blogspot.co.il/2013/01/wireless-deauth-attack-using-aireplay.html

created probAttack python file for combining a Deauth attack with prob requestes and faking proper AP


== dependecies: ==
* first of all please
    sudo echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
    apt dist-upgrade
    apt update
    apt upgrade
    apt update

installing python and scapy!!
apt install python2.7
apt install python-pip
pip install scapy
(maybe will need to install alot of other things like build-essential)

installing aircrack, ip, dnsmasq
apt install ip
sudo apt install aircrack-ng
apt install python-twisted
apt install hostapd
apt install dnsmasq

clone and install scapy-fakeap as describe in the github readme.
git clone https://github.com/rpp0/scapy-fakeap.git
python2 setup.py install

== steps: ==
* importent! you will need two supported wireless net cards for this procedure to work,
  check for supporting monitor mode with your card.
  
* clone this github and cd to it.
  
* before starting, switch your cars to monitor mode using the attached script (monitormode.sh)
    ./monitormode <YOUR FIRST INTERFACE NAME>
    ./monitormode <YOUR SECOND INTERFACE NAME>

* running the attack:
    python probAttack.py -i (YOUR FIRST INTERFACE NAME) -l (YOUR SECOND INTERFACE NAME)
 
 from here the script will guide you,
 if you see no networks, try to rerun the script again after monitoring everythig...
 
 # second part
 using EvilAP_Defender by moha99sa
 after fixing, changing.... KarmaDef.py was created (can see diffs and commits in in the forked reposetory)

* Importent! when installing mysql, give proper username and password (root root) and remember them!
    this will be requaiered when starting the script (here will ask for mysql user and password)
    
== dependecies: ==
sudo apt-get install mysql-server
sudo mysql_secure_installation
sudo apt-get install mysql-client
sudo pip install Netaddr
sudo apt-get install python-pip python-dev libmysqlclient-dev
sudo pip install MySQL-python
sudo pip install mysql-connector==2.1.4

== steps: ==
this is the easy one...
* for learning mode (adding safe APs to whitelist and some more nice options)
    python KaramaDef.py -L
* for normal detection mode (after you got some safe whitelist APs)
    python KaramaDef.py -N
    
 the script will guide you further...
 again, if there is any comprehension problems, try rerun everything.


# Extra Part
here ive been testing Rogue AP Attacks Part 1 - Evil Twin

http://solstice.me/python/wireless/2015/11/01/python-evil-twin/


in "evil_twin" folder you can find the proper python files,
the dependeies are same as above.


this can be useful for listening to connections over specifict AP and getting thier log...!

* follow instructions in the link
* * editing /etc/hostapd/hostapd.conf (this is just an example, edit it with your properties)
    interface=(your monitor interface)
    driver=nl80211
    ssid=(your acces point name)
    hw_mode=g
    channel=6
    macaddr_acl=0
    auth_algs=1
    ignore_broadcast_ssid=0
    wpa=3
    wpa_passphrase=my_password
    wpa_key_mgmt=WPA-PSK
    wpa_pairwise=TKIP
    rsn_pairwise=CCMP
  * END
 
* * Configuration file for dnsmasq, editing /etc/dnsmasq/dnsmasq.conf
    listen-address=127.0.0.1
    log-queries
  * END

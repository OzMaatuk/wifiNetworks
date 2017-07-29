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
    apt dist-upgrade
    apt update
    apt upgrade
    apt update

clone and install scapy-fakeap as describe in the github readme.
git clone https://github.com/rpp0/scapy-fakeap.git
python2 setup.py install

installing python and scapy!!
apt install python2.7
apt install python-pip
pip install scapy
(maybe will need to install alot of other things like build-essential)

* importent! you will need two supported wireless net cards for this procedure to work,
  check for supporting monitor mode with your card.
  
* before starting, switch your cars to monitor mode using 

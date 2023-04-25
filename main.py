#!/usr/bin/env python3

import scapy.layers.l2
import scapy.all
import optparse
import ipaddress


def get_arguments():
    parser = optparse.OptionParser()

    parser.add_option('-r', '--iprange', dest='ip_range', help='IPv4 range to scan for '
                                                               'devices e.g., "192.0.2.1/24"')

    (options, args) = parser.parse_args()

    # check if input for flag exists if we want to require it
    if not options.ip_range:
        parser.error('[-] You must input an ip range to scan. Use --help for more info.')

    # use regex to validate input for either an ip or cidr range
    # p = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(16|24)$)')

    try:
        # Testing if valid ip range instead of using regex
        ipaddress.ip_network(options.ip_range)
        return options.ip_range
    except ValueError:
        parser.error('[-] Must be a valid IP or IP range in CIDR format. Use --help for more info.')




def scan(ip):
    arp_request = scapy.layers.l2.ARP(pdst=ip)
    broadcast = scapy.layers.l2.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    # Returns a couple of 2 lists. We are only interested in answered_list
    # answered_list, unanswered_list = scapy.all.srp(arp_request_broadcast, timeout=1)

    answered_list = scapy.all.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # List comprehension syntax
    return [{'ip': ans[1].psrc, 'mac': ans[1].hwsrc} for ans in answered_list]

    # for answer in answered_list:
    #     scan_dict = {'ip': answer[1].psrc, 'mac': answer[1].hwsrc}
    #     scan_result.append(scan_dict)

    # return scan_result


def display_scan_results(scan_result):
    print('IP\t\t\tMac Address\n------------------------------------------')
    for res in scan_result:
        print(f'IP: {res["ip"]}\t\tMAC: {res["mac"]}')


ip_range = get_arguments()
result = scan(ip_range)
display_scan_results(result)

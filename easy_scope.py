#!/usr/bin/env python
# coding: utf-8
#
# By Leon Johnson - twitter.com/sho_luv
#
# idea came from Jonathan Broche (@g0jhonny)
# https://github.com/gojhonny/Pentesting-Scripts/blob/master/easyscope/easyscope.py

import argparse
import sys
from netaddr import IPNetwork, IPAddress, cidr_merge, AddrFormatError

def expand_range(addr):
    start, end = addr.split('-')
    start, end = IPAddress(start), IPAddress(end)
    while start <= end:
        yield str(start)
        start += 1

def expand(addr):
    if '-' in addr:
        return list(expand_range(addr))
    else:
        return [str(ip) for ip in IPNetwork(addr)]

def combine(addrs):
    networks = []
    for addr in addrs:
        if '-' in addr:
            networks.extend(IPNetwork(ip) for ip in expand_range(addr))
        else:
            networks.append(IPNetwork(addr))
    return [str(net) for net in cidr_merge(networks)]

def main():
    parser = argparse.ArgumentParser(description='A script to combine or expand IP Addresses')
    parser.add_argument('-f', '--file', required=True, help='A new line delimited file containing IP addresses, ranges, or subnets.')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('-e', '--expand', action='store_true', help='Expand IP addresses/ranges into single IP addresses.')
    action.add_argument('-c', '--combine', action='store_true', help='Combine IPs addresses/ranges into supernets.')

    args = parser.parse_args()

    with open(args.file) as f:
        addrs = [line.strip() for line in f]

    if args.expand:
        for addr in addrs:
            try:
                for ip in expand(addr):
                    print(ip)
            except (AddrFormatError, ValueError):
                print(f"[!] Invalid address format: {addr}", file=sys.stderr)
    elif args.combine:
        try:
            for net in combine(addrs):
                print(net)
        except (AddrFormatError, ValueError):
            print(f"[!] Invalid address format in list: {addrs}", file=sys.stderr)

if __name__ == '__main__':
    main()


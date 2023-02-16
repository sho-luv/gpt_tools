#!/usr/bin/python
import argparse
from impacket.smbconnection import SMBConnection
from termcolor import colored

def check_null_session(ip):
    try:
        conn = SMBConnection(ip, ip, timeout=2)
        conn.login('', '')
        conn.logoff()
        print(colored(f"{ip} allows null sessions", 'yellow'))
    except Exception as e:
        pass

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Path to a file containing IP addresses (one per line)')
    group.add_argument('-i', '--ip', nargs='+', help='List of IP addresses to check for null sessions')
    args = parser.parse_args()

    ips = []
    if args.file:
        with open(args.file, 'r') as f:
            ips = [line.strip() for line in f]
    else:
        ips = args.ip

    for ip in ips:
        check_null_session(ip)

if __name__ == '__main__':
    main()


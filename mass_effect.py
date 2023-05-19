#!/usr/bin/env python
# coding: utf-8
# 
# By Leon Johnson - twitter.com/sho_luv
#
# This program takes a file of IP addresses and scans
# them using masscan one port at a time to create files
# named after the service that was scanned. 
# I'm porting overe my mass-effect.sh to python
# https://github.com/sho-luv/mass-effect


import argparse
import subprocess
import os
import sys

# ANSI color codes
RED = "\033[1;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
CYAN = "\033[0;36m"
RESET = "\033[0m"

import os

def run_masscan(service, ports, target, exclude_file, rate):
    print(f"{CYAN}Running masscan on {service} (ports: {ports}){RESET}")

    # Define the iptables rules
    iptables_rule = ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "60000", "-j", "DROP"]

    output_dir = "masseffect_output"
    os.makedirs(output_dir, exist_ok=True)

    try:
        if service == 'http':
            print(" ".join(iptables_rule))
            subprocess.run(iptables_rule)

        cmd = ["masscan", "--open", "-p", ports]
        if os.path.isfile(target):
            cmd.extend(["-iL", target])
        else:
            cmd.append(target)

        if service == 'http':
            cmd.extend(["--source-port", "60000"])

        if exclude_file:
            cmd.extend(["--excludefile", exclude_file])

        if service == 'http':
            cmd.extend(["--banners"])

        cmd.extend(["-oB", os.path.join(output_dir, service)])

        if rate is not None:
            cmd.extend(["--rate", str(rate)])

        print(" ".join(cmd))
        subprocess.run(cmd)

        if service == 'http':
            readscan_cmd = ["masscan", "--readscan", service, "-oX", os.path.join(output_dir, f"{service}.xml")]
            output = subprocess.run(readscan_cmd, capture_output=True, text=True)

            iptables_rule[1] = "-D"
            print(" ".join(iptables_rule))
            subprocess.run(iptables_rule)

        output_file = os.path.join(output_dir, f"{service}.txt")
        if os.path.exists(output_file) and os.path.getsize(output_file) == 0:
            os.remove(output_file)
            
    except FileNotFoundError:
        print(f"{RED}masscan not found. Please install masscan and try again.{RESET}")
        sys.exit(1)

    if service == 'http' and output.stdout.strip():
        with open(os.path.join(output_dir, f"{service}.txt"), 'w') as f:
            for line in output.stdout.split('\n'):
                if line.strip():
                    f.write(line.split(' ')[5] + '\n')


banner = """

 ███    ███  █████  ███████ ███████       ███████ ███████ ███████ ███████  ██████ ████████ 
 ████  ████ ██   ██ ██      ██            ██      ██      ██      ██      ██         ██    
 ██ ████ ██ ███████ ███████ ███████ █████ █████   █████   █████   █████   ██         ██ 
 ██  ██  ██ ██   ██      ██      ██       ██      ██      ██      ██      ██         ██ 
 ██      ██ ██   ██ ███████ ███████       ███████ ██      ██      ███████  ██████    ██ 
                                                                                               

                $BWhite Port Scanner For Things I Like To Hack$Off | $BYellow@sho_luv$Off
"""

from termcolor import colored


def print_banner():
    print(f"{YELLOW}##############################################")
    print(f"#                                            #")
    print(f"#          Masscan Automation Script         #")
    print(f"#                                            #")
    print(f"##############################################{RESET}")

def main():
    print_banner()

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required=True,
                        help='IP address or file of IP addresses to be scanned')
    parser.add_argument('-r', '--rate', default='100', 
                        help='Rate to scan (default is 100 packets per second)')

    parser.add_argument('-e', '--exclude', default='', help='File of IPs to be excluded from scan')

    args = parser.parse_args()

    target = args.target

    services = {
        'smb': '445',
        'http': '80,443,8080,8081',
        'snmp': 'U:161',
        'ike': 'U:500',
        'ipmi': 'U:623',
        'ftp': '21',
        'ssh': '22',
        'nfs': '111',
        'rlogin': '513',
        'ghost_cat': '8009',
        'java-rmi': '1099',
        'mssql': '1433',
        'oracle': '1521',
        'jdwp': '2010,8000,9999',
        'rdp': '3389',
        'erlang': '4369',
        'siet': '4786',
        'vnc': '5900',
        'couchdb': '5984',
        'winrm': '5985,5986',
        'x11': '6000-6005',
        'redis': '6379',
        'weblogic': '7001'
        # Add more services here
    }

    exclude = f"--excludefile {args.exclude}" if args.exclude else ""

    for service, ports in services.items():
        run_masscan(service, ports, target, exclude, args.rate)

if __name__ == "__main__":
    main()


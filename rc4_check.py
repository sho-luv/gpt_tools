#!/usr/bin/env python
# coding: utf-8
#
# By Leon Johnson - twitter.com/sho_luv
#
# This program I wrote with the help of chatGPT
# to scan a file of IP address, hostnames, or CIDR ranges to see if they support RC4

import argparse
import subprocess
from queue import Queue
from threading import Thread
from colorama import init, Fore
import ipaddress

def check_rc4_support(ip):
    try:
        result = subprocess.run(['openssl', 's_client', '-connect', f'{ip}:636', '-cipher', 'RC4'], capture_output=True, text=True, timeout=5)
        if 'Cipher is' in result.stdout:
            return True
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"Error checking {ip}: {e}")

    return False

def worker(queue, verbose, rc4_hosts):
    while not queue.empty():
        ip = queue.get()
        if check_rc4_support(ip):
            print(f"{Fore.YELLOW}{ip} supports RC4{Fore.RESET}")
            rc4_hosts.append(ip)
        elif verbose:
            print(f"{ip} does not support RC4")
        queue.task_done()

def expand_cidr(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def main(file_path, num_threads, verbose):
    # Initialize colorama
    init()

    # Read IP addresses, hostnames, and CIDR ranges from the file
    with open(file_path, 'r') as file:
        input_list = [line.strip() for line in file.readlines()]

    # Expand CIDR ranges and add IP addresses/hostnames to the list
    ip_addresses = []
    for item in input_list:
        if '/' in item:
            ip_addresses.extend(expand_cidr(item))
        else:
            ip_addresses.append(item)

    # Create a queue and add IP addresses to it
    queue = Queue()
    for ip in ip_addresses:
        queue.put(ip)

    # Create a list to store RC4 supported hosts
    rc4_hosts = []

    # Create worker threads and start them
    threads = [Thread(target=worker, args=(queue, verbose, rc4_hosts)) for _ in range(num_threads)]
    for thread in threads:
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # If no RC4 supported hosts were found, print a message
    if not rc4_hosts:
        print("No hosts were found that support RC4.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check IP addresses, hostnames, or CIDR ranges for RC4 support.')
    parser.add_argument('file', help='File containing IP addresses, hostnames, or CIDR ranges, one per line.')
    parser.add_argument('-t', '--threads', type=int, default=4, help='Number of concurrent threads to use.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output. Print all the hosts that do not support RC4.')

    args = parser.parse_args()
    main(args.file, args.threads, args.verbose)


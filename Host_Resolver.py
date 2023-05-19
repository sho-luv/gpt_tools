#!/usr/bin/env python
# coding: utf-8
#
# By Leon Johnson - twitter.com/sho_luv
#
# This program resolves hostnames in parallel, 
# using multiple threads to improve performance.


import argparse
import socket
import threading

def resolve_hostname(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f"{hostname} resolved to {ip_address}")
    except socket.error as e:
        print(f"{hostname} failed to resolve: {e}")

def main():
    parser = argparse.ArgumentParser(description="Resolve hostnames in parallel")
    parser.add_argument("filename", help="file containing hostnames, one per line")
    parser.add_argument("-t", "--threads", type=int, default=10, help="number of threads to use")
    args = parser.parse_args()

    with open(args.filename) as f:
        hostnames = f.read().splitlines()

    threads = []
    for hostname in hostnames:
        thread = threading.Thread(target=resolve_hostname, args=(hostname,))
        threads.append(thread)

    for i in range(0, len(threads), args.threads):
        for thread in threads[i:i+args.threads]:
            thread.start()
        for thread in threads[i:i+args.threads]:
            thread.join()

if __name__ == "__main__":
    main()


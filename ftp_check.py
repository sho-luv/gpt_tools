#!/usr/bin/env python
# coding: utf-8
#
# By Leon Johnson - twitter.com/sho_luv
#
# This program I wrote with the help of chatGPT
# to check anonymous ftp as well as list the file contents 

import argparse
import ftplib
import socket
from pathlib import Path

def check_anonymous_ftp(host, list_contents=False):
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(host, timeout=5)
            ftp.login()  # Attempt anonymous login
            print(f"Anonymous FTP access allowed on {host}")
            if list_contents:
                try:
                    print("Listing directory contents:")
                    ftp.retrlines('LIST')
                except Exception as e:
                    print(f"Error while listing directory contents: {e}")
    except (socket.timeout, ConnectionRefusedError, *ftplib.all_errors) as e:
        print(f"Anonymous FTP access denied or not available on {host} - {e}")


def main():
    parser = argparse.ArgumentParser(description="Check anonymous FTP access on a list of hosts")
    parser.add_argument("file", type=str, help="Path to the file containing a list of hosts")
    parser.add_argument("-l", "--list", action="store_true", help="List the contents of the anonymous FTP directory")

    args = parser.parse_args()

    with open(args.file, "r") as file:
        hosts = file.read().splitlines()

    for host in hosts:
        check_anonymous_ftp(host, list_contents=args.list)


if __name__ == "__main__":
    main()


#!/usr/bin/env python
# coding: utf-8
# 
# By Leon Johnson - twitter.com/sho_luv
#
# This program takes script file used to capture lsa secrets
# using crackmapexec --lsa and pareses out the output to 
# find any cleartext passwords


import argparse
import re

def process_output(output, exclusions):
    for line in output.split("\n"):
        if re.search("SMB", line) and all(re.search(exclusion, line, re.IGNORECASE) is None for exclusion in exclusions):
            print(line)

def main():
    exclusions = [
        r"aad3b",
        r"KeyVault_wsnm_KeyCol",
        r"NETAutoGenKeys",
        r"KeyVault",
        r"pwn3d",
        r"Dumped",
        r"NL\$KM",
        r"aes128",
        r"plain_password_hex",
        r"des-cbc-md5",
        r"aes256-cts-hmac",
        r"\$DCC2\$",
        r"Dumping LSA secrets",
        r"\(SMBv1:",
        r"STATUS_NOT_SUPPORTED",
        r":0x",
    ]

    parser = argparse.ArgumentParser(description='Process input file.')
    parser.add_argument('file', type=argparse.FileType('r'), help='input file')
    args = parser.parse_args()
    input_file = args.file

    process_output(input_file.read(), exclusions)

if __name__ == "__main__":
    main()


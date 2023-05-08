#!/usr/bin/env python
# coding: utf-8
#
# By Leon Johnson - twitter.com/sho_luv
#
# This program I wrote with the help of chatGPT
# to extract http urls from masscan xml files


import xml.etree.ElementTree as ET
import argparse
from urllib.parse import urlparse

def parse_xml_file(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    urls = set()

    for host in root.findall('host'):
        address = host.find('address').get('addr')
        port = host.find('ports').find('port')
        port_id = port.get('portid')
        
        if port_id == '80':
            urls.add(f'http://{address}')
        elif port_id == '443':
            urls.add(f'https://{address}')

    return urls

def main():
    parser = argparse.ArgumentParser(description='Extract URLs from masscan XML output.')
    parser.add_argument('xml_file', type=str, help='Path to the masscan XML file.')

    args = parser.parse_args()

    urls = parse_xml_file(args.xml_file)

    for url in urls:
        print(url)

if __name__ == '__main__':
    main()


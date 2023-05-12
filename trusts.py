#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# By Leon Johnson - twitter.com/sho_luv
#
# This code is a conversion of Brandon Fisher's code
# converted to a standalone project with the help of chatGPT
# to identify domain trusts.

import argparse
import socket
import shutil
from getpass import getpass
from termcolor import colored
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket

def parse_args():
    parser = argparse.ArgumentParser(description="Extract all Trust Relationships and Trusting Direction")
    parser.add_argument('account', action='store', help='[domain/]username[:password] Account used to authenticate to DC.')
    parser.add_argument('--resolve-ip', action='store_true', help='Resolve and save IP addresses of each domain.')
    return parser.parse_args()

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def save_ip(domain, ip):
    if ip is not None:
        with open(f"{domain}.txt", "w") as f:
            f.write(ip)

def main(account, resolve_ip_flag):
    # Assuming the format of 'account' argument is domain/username:password
    domain, account = account.split('/')
    username, password = account.split(':')

    # Create the LDAP connection
    try:
        ldap_connection = ldap_impacket.LDAPConnection('ldap://{}'.format(domain), domain)
        ldap_connection.login(username, password)
    except ldap_impacket.LDAPSessionError as e:
        print('Failed to connect: {}'.format(e))
        return

    # Get the base DN for the domain
    domain_dn = ','.join(['DC=' + dc for dc in domain.split('.')])

    # Search for all trust relationships
    search_filter = '(&(objectClass=trustedDomain))'
    attributes = ['flatName', 'trustPartner', 'trustDirection']
    try:
        print('Search Filter={}'.format(search_filter))
        resp = ldap_connection.search(searchBase=domain_dn, searchFilter=search_filter, attributes=attributes, sizeLimit=0)
    except ldap_impacket.LDAPSearchError as e:
        if e.getErrorString().find('sizeLimitExceeded') >= 0:
            print('sizeLimitExceeded exception caught, giving up and processing the data received')
            resp = e.getAnswers()
        else:
            print(e)
            return

    trusts = []
    print('Total of records returned {}'.format(colored(str(len(resp)), 'yellow')))

    for item in resp:
        if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
            continue
        flat_name = ''
        trust_partner = ''
        trust_direction = ''
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'flatName':
                    flat_name = str(attribute['vals'][0])
                elif str(attribute['type']) == 'trustPartner':
                    trust_partner = str(attribute['vals'][0])
                elif str(attribute['type']) == 'trustDirection':
                    if str(attribute['vals'][0]) == '1':
                        trust_direction = colored('Inbound', 'blue')
                    elif str(attribute['vals'][0]) == '2':
                        trust_direction = colored('Outbound', 'yellow')
                    elif str(attribute['vals'][0]) == '3':
                        trust_direction = colored('Bidirectional', 'green')
            if flat_name != '' and trust_partner != '' and trust_direction != '':
                trusts.append((flat_name, trust_partner, trust_direction))
        except Exception as e:
            print('Cannot process trust relationship due to error {}'.format(str(e)))

    # Get terminal width
    term_width = shutil.get_terminal_size()[0]
    term_width = 70

    if len(trusts) > 0:
        print(colored('The {} domain has the following trust relationships:'.format(colored(domain, 'yellow'))))
        for trust in trusts:
            # Calculate arrow length
            arrow_len = term_width - len(trust[1]) - len(trust[2]) - 6
            if arrow_len > 0:  # Check if space for arrow exists
                arrow = '-' * arrow_len
                print('{} {}> {}'.format(colored(trust[1], 'blue'), arrow, colored(trust[2], 'red')))
                if resolve_ip_flag:
                    ip = resolve_ip(trust[1])
                    print('Resolved IP for {}: {}'.format(colored(trust[1], 'blue'), ip))
                    save_ip(trust[1], ip)
            else:  # If not enough space for arrow, print normally
                print('{} -> {}'.format(colored(trust[1], 'blue'), colored(trust[2], 'red')))
                if resolve_ip_flag:
                    ip = resolve_ip(trust[1])
                    print('Resolved IP for {}: {}'.format(colored(trust[1], 'blue'), ip))
                    save_ip(trust[1], ip)
    else:
        print(colored('No trust relationships found', 'red'))

if __name__ == "__main__":
    args = parse_args()
    main(args.account, args.resolve_ip)



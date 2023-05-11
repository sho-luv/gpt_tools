#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# By Leon Johnson - twitter.com/sho_luv
# 
# This code is a conversion of Brandon Fisher's code
# converted to a standalone project with the help of chatGPT
# to identify domain trusts.



import argparse
from getpass import getpass
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket

def parse_args():
    parser = argparse.ArgumentParser(description="Extract all Trust Relationships and Trusting Direction")
    parser.add_argument('account', action='store', help='[domain/]username[:password] Account used to authenticate to DC.')
    return parser.parse_args()

def main(account):
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
    print('Total of records returned {}'.format(len(resp)))
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
                        trust_direction = 'Inbound'
                    elif str(attribute['vals'][0]) == '2':
                        trust_direction = 'Outbound'
                    elif str(attribute['vals'][0]) == '3':
                        trust_direction = 'Bidirectional'
            if flat_name != '' and trust_partner != '' and trust_direction != '':
                trusts.append((flat_name, trust_partner, trust_direction))
        except Exception as e:
            print('Cannot process trust relationship due to error {}'.format(str(e)))

    if len(trusts) > 0:
        print('Found the following trust relationships:')
        for trust in trusts:
            print('{} -> {}'.format(trust[1], trust[2]))
    else:
        print('No trust relationships found')

if __name__ == "__main__":
    args = parse_args()
    main(args.account)


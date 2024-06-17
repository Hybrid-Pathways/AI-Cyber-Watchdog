import os
import json
import socket

from shodan import Shodan
from settings import SHODAN_API_KEY

api = Shodan(SHODAN_API_KEY)

def shodan_org_scan(query: str) -> str:
    report = ''

    # Check if the query is a list of IPs
    if ',' in query:
        ips = query.split(',')
        for ip in ips:
            ip = ip.strip()  # remove any leading or trailing whitespace
            host = api.host(ip, minify=True, history=False)
            report += '\nIP: {0}, Hostnames: {1}, Ports: {2}, Operating System: {3}.'.format(ip, host['hostnames'], host['ports'], host['os'])
    # Check if the query is a hostname
    elif '.' in query:
        try:
            ip = socket.gethostbyname(query)
            host = api.host(ip, minify=True, history=False)
            report += '\nIP: {0}, Hostnames: {1}, Ports: {2}, Operating System: {3}.'.format(ip, host['hostnames'], host['ports'], host['os'])
        except socket.gaierror:
            report += '\nUnable to resolve hostname: {}'.format(query)
    # Assume the query is a company name
    else:
        result = api.search(query)
        for service in result['matches']:
            host = api.host(service['ip_str'], minify=True, history=False)
            report += '\nIP: {0}, Hostnames: {1}, Ports: {2}, Operating System: {3}.'.format(service['ip_str'], host['hostnames'], host['ports'], host['os'])

    report = report.replace('None.', 'Unknown.')
    return report
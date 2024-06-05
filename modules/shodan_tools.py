import os
import json
import socket

from shodan import Shodan
from config import SHODAN_API_KEY

api = Shodan(SHODAN_API_KEY)


import socket

def shodan_org_scan(query: str) -> str:
    report = ''
    ipList = []

    # Check if the query is a list of IPs
    if ',' in query:
        ips = query.split(',')
        for ip in ips:
            ip = ip.strip()  # remove any leading or trailing whitespace
            host = api.host(ip, minify=True, history=False)
            openPorts = []
            for port in host['ports']:
                openPorts.append(port)
            hostnameList = []
            for hostname in host['hostnames']:
                hostnameList.append(hostname)
            report += '\nIP: {0}, Hostnames: {1}, Ports: {2}, Operating System: {3}.'.format(ip, hostnameList, openPorts, host['os'])
    # Check if the query is a hostname
    elif '.' in query:
        try:
            ip = socket.gethostbyname(query)
            host = api.host(ip, minify=True, history=False)
            openPorts = []
            for port in host['ports']:
                openPorts.append(port)
            hostnameList = []
            for hostname in host['hostnames']:
                hostnameList.append(hostname)
            report += '\nIP: {0}, Hostnames: {1}, Ports: {2}, Operating System: {3}.'.format(ip, hostnameList, openPorts, host['os'])
        except socket.gaierror:
            report += '\nUnable to resolve hostname: {}'.format(query)
    # Assume the query is a company name
    else:
        result = api.search(query)
        for service in result['matches']:
            host = api.host(service['ip_str'], minify=True, history=False)
            openPorts = []
            for port in host['ports']:
                openPorts.append(port)
            hostnameList = []
            for hostname in host['hostnames']:
                hostnameList.append(hostname)
            report += '\nIP: {0}, Hostnames: {1}, Ports: {2}, Operating System: {3}.'.format(service['ip_str'], hostnameList, openPorts, host['os'])

    report = report.replace('None.', 'Unknown.')
    return report
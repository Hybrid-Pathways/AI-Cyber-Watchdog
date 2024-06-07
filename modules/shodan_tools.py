import os
import pandas as pd
import json
import socket
import requests

from shodan import Shodan
from bs4 import BeautifulSoup
from config import SHODAN_API_KEY

api = Shodan(SHODAN_API_KEY)
cmdb_df = pd.read_csv("./CMDB/Application_CMDB.csv")

def fetch_cve_details(cve_id):
    url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
    try:
        response = requests.get(url)
        response.raise_for_status()  # Ensure we got a successful response
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extracting the CVE description
        description_tag = soup.find('p', {'data-testid': 'vuln-description'})
        description = description_tag.text if description_tag else 'Description not available'
        
        # Extracting the CVSS score
        cvss_score_link = soup.find('a', href=lambda href: href and "vector=AV:" in href)
        if cvss_score_link:
            cvss_vector = cvss_score_link['href']
            cvss_score = cvss_vector.split('vector=AV:')[1].split('/')[0]
        else:
            cvss_score = 'N/A'
        
        return description, cvss_score
    except requests.RequestException as e:
        return f'Error fetching details for {cve_id}: {e}', 'N/A'

def CMDB_ip_check(ip):
    ip_list = cmdb_df['application_ip'].tolist()
    return ip in ip_list


def shodan_org_scan(query: str) -> str:
    report = ''
    host = None  # Initialize host to None

    if ',' in query:
        ips = query.split(',')
        for ip in ips:
            ip = ip.strip()

            if not CMDB_ip_check(ip):
                #This IP is not found in the CMDB
                print(f"\n***WARNING*** IP {ip} not found in CMDB, excluding from report")
                continue
            
            #proceed if IP is found
            host = api.host(ip, minify=False, history=False)
            print(host)
            report += f'\nIP: {ip}, Hostnames: {host["hostnames"]}, Ports: {host["ports"]}, Operating System: {host["os"]}, ISP Info: {host["isp"]}, Country: {host["country_name"]}'
            if "vulns" in host:
                report += ', CVE Info: '
                for cve in host["vulns"]:
                    if cve.startswith('CVE-'):  # Ensure it's a CVE ID
                        cve_description = fetch_cve_details(cve)
                        report += f'\n\t{cve}: {cve_description}'
                if "tags" in host:
                    report += f', Tags: {host["tags"]}'

    elif '.' in query:
        try:
            ip = socket.gethostbyname(query)

            if not CMDB_ip_check(ip):
                #This IP is not found in the CMDB
                print(f"\n***WARNING*** The IP corresponding with domain {query} is {ip}")
                print(f"***WARNING*** IP {ip} not found in CMDB, excluding from report")

            host = api.host(ip, minify=True, history=False)
            #print(host)
            report += f'\nIP: {ip}, Hostnames: {host["hostnames"]}, Ports: {host["ports"]}, Operating System: {host["os"]}, ISP Info: {host["isp"]} Country: {host["country_name"]}'
            if "vulns" in host:
                report += ', CVE Info: '
                for cve in host["vulns"]:
                    if cve.startswith('CVE-'):
                        cve_description = fetch_cve_details(cve)
                        report += f'\n\t{cve}: {cve_description}'
            if "tags" in host:
                report += f', Tags: {host["tags"]}'
        except socket.gaierror:
            report += '\nUnable to resolve hostname: {}'.format(query)
    else:
        result = api.search(query)
        #print(result)
        for service in result['matches']:
            
            if not CMDB_ip_check(service['ip_str']):
                #This IP is not found in the CMDB
                print(f"\n ***WARNING*** IP {service['ip_str']} not found in CMDB, excluding from report")
                continue

            host = api.host(service['ip_str'], minify=True, history=False)
            report += '\nIP: {0}, Hostnames: {1}, Ports: {2}, Operating System: {3}.'.format(service['ip_str'], host['hostnames'], host['ports'], host['os'])
            print("\nIP: {0}, Hostnames: {1}, Ports: {2}, Operating System: {3}.".format(service['ip_str'], host['hostnames'], host['ports'], host['os']))
            if "vulns" in host:
                report += ', CVE Info: '
                for cve in host["vulns"]:
                    if cve.startswith('CVE-'):
                        cve_description = fetch_cve_details(cve)
                        report += f'\n\t{cve}: {cve_description}'

    report = report.replace('None.', 'Unknown.')
    return report
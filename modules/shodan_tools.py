import os
import pandas as pd
import json
import socket
import requests

from shodan import Shodan, exception
from bs4 import BeautifulSoup
from config import SHODAN_API_KEY

api = Shodan(SHODAN_API_KEY)
cmdb_df = pd.read_csv("./CMDB/Application_CMDB.csv")
vuln_df = pd.read_csv("./CMDB/Vulnearbility_report.csv")

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

def CMDB_OS_check(ip):
    mask = (cmdb_df['application_ip'] == ip)
    return cmdb_df[mask]['operating_system'].tolist()[0]

def vuln_lookup_ip(ip):
    mask = (vuln_df['ip_addr']==ip)
    return vuln_df[mask]['open_ports'].tolist()

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

            vuln_port_list = vuln_lookup_ip(ip)
            
            #proceed if IP is found
            host = api.host(ip, minify=False, history=False)
            print(f'\nIP: {ip}, Hostnames: {host["hostnames"]}, Ports: {host["ports"]}, Operating System: {host["os"]}, ISP Info: {host["isp"]}, Country: {host["country_name"]}')
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
                return report
            
            try:
                host = api.host(ip, minify=True, history=False)
            
            except exception.APIError:
                print(f"\n ***WARNING*** IP {ip} not found in Shodan. Retrying 3 times")
                for i in range(3):
                    try:
                        host = api.host(ip, minify=True, history=False)
                    except Exception as e  :
                        continue
                    else:
                        break
                if (i == 2):
                    print(f"\n ***WARNING*** IP {ip} not found in Shodan after 3 retries, excluding from report")
                    return report

            output_port_list = host["ports"]
            vuln_port_set = set(vuln_lookup_ip(ip))
            shodan_port_set = set(host["ports"])

            if(vuln_port_set != shodan_port_set):
                print("\nshodan_port_list: "+str(shodan_port_set))
                print("Vuln report_port list: "+ str(vuln_port_set))
                print("\n***WARNING***")
                print("1. Shodan reported potential false positive in open ports")
                port_intersection = vuln_port_set.intersection(shodan_port_set)
                print(f"2. Ports shared by both shodan and vulnerability reports: {(port_intersection)}")
                print(f"3. Ports reported by shodan but not in vulnerability reports: {shodan_port_set - vuln_port_set}")
                output_port_list = list(port_intersection)

            print(f'\nIP: {ip}, Hostnames: {host["hostnames"]}, Ports: {output_port_list}, Operating System: {host["os"]}, ISP Info: {host["isp"]}, Country: {host["country_name"]}')
            report += f'\nIP: {ip}, Hostnames: {host["hostnames"]}, Ports: {output_port_list}, Operating System: {host["os"]}, ISP Info: {host["isp"]} Country: {host["country_name"]}'
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

            try:
                host = api.host(service['ip_str'], minify=True, history=False)
            
            except exception.APIError:
                print(f"\n ***WARNING*** IP {service['ip_str']} not found in Shodan. Retrying 3 times")
                for i in range(3):
                    try:
                        host = api.host(service['ip_str'], minify=True, history=False)
                    except Exception as e  :
                        continue
                    else:
                        break
                if (i == 2):
                    print(f"\n ***WARNING*** IP {service['ip_str']} not found in Shodan after 3 retries, excluding from report")
                    continue

            os_used = host["os"]            
            cmdb_os = CMDB_OS_check(service['ip_str'])
            if (host["os"] is None):
                os_used = cmdb_os
            
            report += f'\nIP: {service["ip_str"]}, Hostnames: {host["hostnames"]}, Ports: {host["ports"]}, Operating System: {os_used}, ISP Info: {host["isp"]} Country: {host["country_name"]}'
            print(f'\nIP: {service["ip_str"]}, Hostnames: {host["hostnames"]}, Ports: {host["ports"]}, Operating System: {os_used}, ISP Info: {host["isp"]} Country: {host["country_name"]}')
            if "vulns" in host:
                report += ', CVE Info: '
                for cve in host["vulns"]:
                    if cve.startswith('CVE-'):
                        cve_description = fetch_cve_details(cve)
                        report += f'\n\t{cve}: {cve_description}'

    report = report.replace('None.', 'Unknown.')
    return report
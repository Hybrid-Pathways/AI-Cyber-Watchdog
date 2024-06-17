
import os
import datetime

from ollama import Client
from settings import OLLAMA_HOST, LLM_MODEL

import modules.shodan_tools as shodan_tools

client = Client(host=OLLAMA_HOST)
llm_model = LLM_MODEL


def get_current_time():
    now = datetime.datetime.now()
    return str(now.day) + str(now.month) + str(now.year) + str(now.hour) + str(now.minute) + str(now.second)


def get_shodan_report(company_name):
    return shodan_tools.shodan_org_scan(company_name)


def get_full_report(shodan_report):
    stream = client.chat(
        model=llm_model,
        messages=[
            {
                'role': 'user',
                'content': f'Here is a report from Shodan: {shodan_report}. Given your expertise as Security Analyst , provide a summary of this report with the folowing requirements:'
                           f'1. For all IP Addresses in the report , detail the steps of mitigation in a numbered list, provide suggested tools and process for performing mitigation tasks for each step.'
                           f'2. For Operating Systems detected or provided from CMDB, provide a list of services running on open ports. If ssh is detected, provide all applicable CVEs and CVSS scores.'
                           f'3. For CVEs returned in the Shodan report, provide the description of the CVE and the CVSS score, if no CVEs provided generate a list of potential CVEs that may apply.'
                           f'4. Try to determine if the IP or Hostname is associated with a cloud service provider (using the "ISP Info:" field in the report), supply a bulleted list of CIS benchmarks and NIST controls https://csrc.nist.gov/pubs/sp/800/ with versions that may apply.'
                           f'5. For open ports, provide a list of potential services that may be running on the ports, provide a list of potential vulnerabilities that may be associated with the services.'
                           f'6. Also note that if you are seeing ports 443 and/or 8443, it could be a load balancer, if a cloud provider was detected list their load balancer services otherwise provide a list of potential load balancers that may be in use.'
            }
        ],
        stream=True,
    )
    full_report = ''
    for chunk in stream:
        print(chunk['message']['content'], end='', flush=True)
        full_report += chunk['message']['content']
    return full_report


def write_report_to_file(file_name, company_name, shodan_report, full_report):
    # Define the directory
    directory = "reports"

    # Check if the directory exists, if not, create it
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Append the directory to the file name
    file_path = os.path.join(directory, file_name)

    # Write to the file in the directory
    with open(file_path, "a") as file:
        file.write(f"\nSearch for: {company_name}\n\n\n")
        file.write(shodan_report)
        file.write("\n\n\n")
        file.write(full_report)

def main():
    while True:
        current_time = get_current_time()
        print("Provide a company name, single IP, list of IPs, or hostname(s) to search Shodan.")
        company_name = input('\nEnter Data: ').strip()  # Use .strip() to remove leading/trailing whitespace

        if not company_name:  # Check if the input is empty
            print("No input provided.") 
            continue  # Skip the rest of the loop and prompt for input again
        
        print("\nShodan Report:\n")
        shodan_report = get_shodan_report(company_name)
        #print(f'\nShodan Report:\n{shodan_report}\n\n')
        if shodan_report:

            full_report = get_full_report(shodan_report)
            file_name = f"shodan_report_{current_time}.txt"
            write_report_to_file(file_name, company_name, shodan_report, full_report)
        else:
            print("Information not found.")
        print("\n\n Report Analysis Completed!\n\n")


if __name__ == "__main__":
    with open('watchdog.ascii', 'r') as file:
        print(file.read())
    main()
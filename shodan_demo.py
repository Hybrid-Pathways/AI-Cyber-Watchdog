
import os
import datetime

from ollama import Client
from config import OLLAMA_HOST, LLM_MODEL

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
                'content': f'Here is a report from Shodan: {shodan_report} Provide a summary of this report. Then, detail steps of mitigation in bullet format, Also provide any applicable CVEs. Try to determine if the IP or Hostname is associated with a cloud service provider and any CIS benchmarks that may apply.'
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
        company_name = input('\nEnter Data: ')
        shodan_report = get_shodan_report(company_name)
        print(f'\nShodan Report:\n{shodan_report}\n\n')
        if shodan_report:
            full_report = get_full_report(shodan_report)
            file_name = f"shodan_report_{current_time}.txt"
            write_report_to_file(file_name, company_name, shodan_report, full_report)
        else:
            print("Information not found.")
        print("Done!\n\n")


if __name__ == "__main__":
    with open('watchdog.ascii', 'r') as file:
        print(file.read())
    main()
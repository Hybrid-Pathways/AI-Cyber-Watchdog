import os
import datetime

#import cisa_demo
#import cisa_search

import pastebin
import shodan_tools

from ollama import Client
from dotenv import load_dotenv

with open('watchdog.ascii', 'r') as file:
    print(file.read())

load_dotenv()

OLLAMA_HOST = os.getenv('OLLAMA_HOST')

client = Client(host=OLLAMA_HOST)

llm_model = 'llama3'

while True:
    fdtn = str((datetime.datetime.now().day)) + str((datetime.datetime.now().month)) + str((datetime.datetime.now().year)) + str((datetime.datetime.now().hour)) + str((datetime.datetime.now().minute)) + str((datetime.datetime.now().second))
    companyName = str(input('\nEnter company name: '))
    shodanReport = shodan_tools.shodan_org_scan(companyName)
    print('\nShodan Report:\n{0}\n\n'.format(shodanReport))
    fullReport = ''
    if len(shodanReport) > 0:
        stream = client.chat(
            model=llm_model,
            messages=[{'role': 'user', 'content': 'Here is a report from Shodan: {0} Provide a summary of this report. Then, detail steps of mitigation in bullet format'.format(shodanReport)}],
            stream=True,
        )
        for chunk in stream:
            print(chunk['message']['content'], end='', flush=True)
            fullReport = fullReport + chunk['message']['content']
        file = open("shodan_report_{0}.txt".format(fdtn), "a")
        file.write("\nSearch for: {0}".format(companyName))
        file.write("\n\n\n")
        file.write(shodanReport)
        file.write("\n\n\n")
        file.write(fullReport)
        file.close()
        pastebin.SearchPastebin(companyName)
    else:
        print("Information not found.")
        pastebin.SearchPastebin(companyName)
    print("Done!\n\n")

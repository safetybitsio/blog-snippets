import argparse
import requests
import csv
import json

#
# Parsing arguments
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--devices", default = "inventory.csv", help = "Devices file in csv format. Default: inventory.csv.")
parser.add_argument("-o", "--output",  default = "output.json", help = "Output file where to store the json response. Default: output.json.")
parser.add_argument("-k", "--apikey", required=True, help = "NIST NVD API Key.")
args = parser.parse_args()
#
devices_csv = args.devices
output_file = args.output
apikey = args.apikey

#
# Reading devices file
inventory = []
with open(devices_csv, newline='') as csvfile:
    inventoryreader = csv.reader(csvfile, delimiter=',', quotechar='"')
    for row in inventoryreader:
        device = {}
        device['name'] = row[0]
        device['vendor'] = row[1]
        device['software'] = row[2]
        device['version'] = row[3]
        device['part'] = row[4]
        device['cpe'] = "cpe:2.3:" + device['part'] + ":" + device['vendor'] + ":" + device['software'] + ":" + device['version']
        device["cves"] = []
        inventory.append(device)

#
# Calling JSON API for each device
data = []
for device in inventory:
    # The API endpoint
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" + device['cpe']

    # Send a GET request to the API
    response = requests.get(url, headers={"apiKey": apikey})
    # Process the response
    vulnerabilities = response.json()["vulnerabilities"]
    for vulnerability in vulnerabilities:
        cve = {}
        cve["id"] = vulnerability["cve"]["id"]
        cve["url"] = "url: https://nvd.nist.gov/vuln/detail/" + cve["id"]
        # Try to grab CVSS Score v3.1
        if "metrics" in vulnerability["cve"] and "cvssMetricV31" in vulnerability["cve"]["metrics"]:
            cve["baseScore"] = vulnerability["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            cve["baseSeverity"] = vulnerability["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        device["cves"].append(cve)
    #
    data.append(device)

#
# Output the result
with open(output_file, 'w') as f:
    json.dump(data, f)

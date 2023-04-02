import csv
import json
import requests

# Define API endpoints for various security advisories and databases
endpoints = {
    'GitHub Security Advisories': 'https://api.github.com/repos/{owner}/{repo}/vulnerability-alerts',
    'PyPI Advisory Database': 'https://pypi.org/advisory/{advisory_id}/json',
    'Go Vulnerability Database': 'https://golang.org/api/security',
    'Rust Advisory Database': 'https://rustsec.org/api/advisories',
    'Global Security Database': 'https://www.cvedetails.com/json-feed.php?numrows=30',
    'OSS-Fuzz': 'https://oss-fuzz.com/v2/vulnerabilities.json',
    'LoopBack Advisory Database': 'https://loopback.io/security-advisories/feed.json'
}

# Define GitHub repository to retrieve Security Advisories from
owner = 'openai'
repo = 'ai-dungeon'

# Send requests to retrieve security data from various databases
data = []
for endpoint, url in endpoints.items():
    if endpoint == 'GitHub Security Advisories':
        response = requests.get(url.format(owner=owner, repo=repo))
        json_data = response.json()['vulnerabilities']
        
        for item in json_data:
            row = {
                'Database': endpoint,
                'Title': item['title'],
                'Description': item['description'],
                'CVEs': item['references']['url']
            }
            data.append(row)
    elif endpoint == 'PyPI Advisory Database':
        response = requests.get(url.format(advisory_id=1))
        json_data = response.json()
        
        for item in json_data['details']:
            row = {
                'Database': endpoint,
                'Title': item['title'],
                'Description': item['description'],
                'CVEs': item['cve'],
            }
            data.append(row)
    elif endpoint == 'Go Vulnerability Database':
        response = requests.get(url)
        json_data = response.json()
        
        for item in json_data:
            row = {
                'Database': endpoint,
                'Title': item['Title'],
                'Description': item['Description'],
                'CVEs': item['CVEs'],
            }
            data.append(row)
    elif endpoint == 'Rust Advisory Database':
        response = requests.get(url)
        json_data = response.json()
        
        for item in json_data:
            row = {
                'Database': endpoint,
                'Title': item['advisory']['title'],
                'Description': item['advisory']['description'],
                'CVEs': item['advisory']['cves'],
            }
            data.append(row)
    elif endpoint == 'Global Security Database':
        response = requests.get(url)
        json_data = response.json()['data']
        
        for item in json_data:
            row = {
                'Database': endpoint,
                'Title': item['vtitle'],
                'Description': item['vulnerable_products'],
                'CVEs': item['cve_id'],
            }
            data.append(row)
    elif endpoint == 'OSS-Fuzz':
        response = requests.get(url)
        json_data = response.json()['vulnerabilities']
        
        for item in json_data:
            row = {
                'Database': endpoint,
                'Title': item['name'],
                'Description': item['description'],
                'CVEs': item['cvss2_score'],
            }
            data.append(row)
    elif endpoint == 'LoopBack Advisory Database':
        response = requests.get(url)
        json_data = response.json()
        
        for item in json_data:
            row = {
                'Database': endpoint,
                'Title': item['title'],
                'Description': item['description'],
                'CVEs': item['cve'],
            }
            data.append(row)

# Write retrieved data to a CSV file
with open('security_data.csv', 'w', newline='') as outfile:
    writer = csv.DictWriter(outfile, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)

# Convert data to JSON and write to output.json file
with open('security_data.json', 'w') as f:
    json.dump(data, f, indent=4)

# Convert data to Markdown and write to output.md file
with open('security_data.md', 'w') as f:
    # Write table header
    f.write("| ")
    for key in data[0]:
        f.write(key + " | ")
    f.write("\n")
    f.write("| ")
    for _ in range(len(data[0])):
        f.write("--- | ")
    f.write("\

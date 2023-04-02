import requests
import csv
import time

# define the base URL and parameters for the NVD API
base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
results_per_page = 2000
start_index = 0

# create a CSV file and write the header row
with open("cve_list.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["CVE ID", "Description", "Published Date"])

    # loop through the pages in the NVD API until all results are retrieved
    while True:
        params = {"resultsPerPage": str(results_per_page), "startIndex": str(start_index)}
        response = requests.get(base_url, params=params)
        cves = response.json()

        # check if there are any more CVEs to retrieve
        if len(cves["result"]["CVE_Items"]) == 0:
            break

        # write each CVE to the CSV file
        for cve in cves["result"]["CVE_Items"]:
            cve_id = cve["cve"]["CVE_data_meta"]["ID"]
            description = cve["cve"]["description"]["description_data"][0]["value"]
            published_date = cve["publishedDate"]
            writer.writerow([cve_id, description, published_date])

        # increment the start index for the next page
        start_index += results_per_page

        # pause for 1 second in between requests to avoid overloading the API
        time.sleep(1)

print("CVE list exported to cve_list.csv")

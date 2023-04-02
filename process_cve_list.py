import csv

with open('allitems.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    next(reader)  # skip the header row
    for row in reader:
        cve_id = row[0]
        # process the CVE ID as per your requirement

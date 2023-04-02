import csv
import sys

with open(sys.argv[1], newline='') as csvfile:
    reader = csv.reader(csvfile)
    next(reader)  # skip the header row
    for row in reader:
        cve_id = row[0]
        # process the CVE ID as per your requirement

name: Update CVE list

on:
  schedule:
    - cron: "0 0 * * *"

jobs:
  update-cve-list:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: "3.x"
      - name: Install dependencies
        run: pip install requests
      - name: Run Python script
        run: python get_cve_list.py
      - name: Commit changes
        uses: EndBug/add-and-commit@v7
        with:
          author_name: "GitHub Actions"
          author_email: "actions@github.com"
          message: "Update CVE list"
          add: "cve_list.csv"
          branch: "cve-list-updates"

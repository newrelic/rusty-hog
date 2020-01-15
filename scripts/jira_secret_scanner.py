import requests
import logging
import re
import tempfile
import os
import subprocess
import uuid
import json
import gzip
import sys
from collections import defaultdict

if len(sys.argv) == 2 and sys.argv[1].startswith("--log="):
    loglevel = sys.argv[1][6:]
else:
    loglevel = "WARNING"

numeric_level = getattr(logging, loglevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)
logging.basicConfig(level=numeric_level)

INSIGHTS_INSERT_KEY = os.environ["INSIGHTS_INSERT_KEY"]
JIRA_TOKEN = os.environ["JIRA_TOKEN"]
ANKAMALI_HOG_PATH = os.environ["ANKAMALI_HOG_PATH"]
INSIGHTS_ACCT_ID = os.environ["INSIGHTS_ACCT_ID"]

headers = {'Authorization':f"Basic {JIRA_TOKEN}"}
search_query = 'updatedDate >= startOfDay()'
start_num=0
url = f"https://newrelic.atlassian.net/rest/api/2/search?jql={search_query}&startAt={start_num}"

issues = []
r = requests.get(url, headers=headers)
result = r.json()
total = result['total']
issues.extend(result['issues'])
while len(issues) < total:
    start_num += result['maxResults']
    logging.info(f"Retrieving results {start_num}-{start_num+result['maxResults']} of {total}")
    url = f"https://newrelic.atlassian.net/rest/api/2/search?jql={search_query}&startAt={start_num}"
    r = requests.get(url, headers=headers)
    result = r.json()
    issues.extend(result['issues'])

gdoc_re = re.compile(r'https://docs.google.com/[^\s|\]]+', re.IGNORECASE)
links = defaultdict(set)

for issue in issues:
    description = issue['fields']['description']
    if not description:
        continue
    matches = gdoc_re.findall(description)
    for match in matches:
        links[issue['key']].add(match)

for issue in issues:
    url = f"https://newrelic.atlassian.net/rest/api/2/issue/{issue['key']}/comment"
    r = requests.get(url, headers=headers)
    comments = r.json()['comments']
    for comment in comments:
        matches = gdoc_re.findall(comment['body'])
        for match in matches:
            links[issue['key']].add(match)

tempdir = tempfile.gettempdir()
gdoc_id_re = re.compile(r'https://docs.google.com/\w+/d/([a-zA-Z0-9-_]+)/?.*',re.IGNORECASE)
output = []

for x in links.items():
    filename = os.path.join(tempdir, str(uuid.uuid4()))
    results = []
    for gdoc_link in x[1]:
        gdocid = gdoc_id_re.match(gdoc_link).group(1)
        s = subprocess.run(
            [
                ANKAMALI_HOG_PATH,
                "--outputfile",
                filename,
                gdocid
            ],
            capture_output=True,
        )
        results.append({"gdoc_link": gdoc_link, "results": filename, "key": x[0]})
    output.extend(results)

logging.info(f"len(output) = {len(output)}")


# the last block of work, iterate through each JSON file from choctaw_hog and put the results in Insights
output_array = []
for result_dict in output:
    try:
        f = open(result_dict["results"], "r")
    except:
        logging.debug("failed to open " + result_dict["results"])
        continue

    with f:
        result_list = json.load(f)
        for finding in result_list:
            output_array.append(
                {
                    "eventType": "secret_scanner_GDrive",
                    "jira_key": result_dict["key"],
                    "g_drive_id": finding["g_drive_id"],
                    "url": finding["web_link"],
                    "reason": finding["reason"]
                }
            )

url = "https://insights-collector.newrelic.com/v1/accounts/{INSIGHTS_ACCT_ID}/events"
headers = {
    "Content-Type": "application/json",
    "X-Insert-Key": INSIGHTS_INSERT_KEY,
    "Content-Encoding": "gzip",
}
post = gzip.compress(json.dumps(output_array).encode("utf-8"))
logging.info(f"len(output_array) = {len(output_array)}")
logging.debug(output_array)
r = requests.post(url, data=post, headers=headers)
logging.info(f"insights status code: {r.status_code}")
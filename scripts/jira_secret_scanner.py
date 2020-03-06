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
result = None
try:
    result = r.json()
except:
    print(f"JIRA error: {r.text}")
    sys.exit(1)
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

logging.info("Reading issue descriptions...")
for issue in issues:
    description = issue['fields']['description']
    if not description:
        continue
    matches = gdoc_re.findall(description)
    for match in matches:
        links[issue['key']].add(match)

logging.info("Retrieving issue comments...")
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

logging.info("Running ankamali hog on each Google Drive link found in Jira...")
for x in links.items():
    logging.debug(f"x: {str(x)}")
    filename = os.path.join(tempdir, str(uuid.uuid4()))
    results = []
    for gdoc_link in x[1]:
        logging.debug(f"gdoc_link: {gdoc_link}")
        logging.debug(f"gdoc_id_re.match(gdoc_link): {str(gdoc_id_re.match(gdoc_link))}")
        gdoc_id_match = gdoc_id_re.match(gdoc_link)
        if not gdoc_id_match:
            continue
        gdocid = gdoc_id_match.group(1)
        s = subprocess.run(
            [
                ANKAMALI_HOG_PATH,
                "--outputfile",
                filename,
                gdocid
            ],
            capture_output=True
        )
        logging.debug(f"ankamali hog output: {s.stdout}")
        if s.returncode != 0:
            logging.warning(f"ankamali hog exited with a non-zero status code: {s.stdout} {s.stderr}")
        # TODO: add better error handling here. some will fail because you don't have
        # permission to the doc. others will fail because you setup your token wrong.
        results.append({"gdoc_link": gdoc_link, "results": filename, "key": x[0]})
    output.extend(results)

logging.info(f"len(output) = {len(output)}")


# the last block of work, iterate through each JSON file from choctaw_hog and put the results in Insights
output_array = []
for result_dict in output:
    try:
        f = open(result_dict["results"], "r")
    except:
        # TODO: add better error handling here. the file won't exist if we couldn't
        # access the file
        logging.warning("failed to open " + result_dict["results"])
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
    os.remove(result_dict["results"])

url = f"https://insights-collector.newrelic.com/v1/accounts/{INSIGHTS_ACCT_ID}/events"
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

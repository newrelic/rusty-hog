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
import datetime
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
JIRA_USERNAME = os.environ["JIRA_USERNAME"]
JIRA_PASSWORD = os.environ["JIRA_PASSWORD"]
JIRA_URL = os.environ["JIRA_URL"]
ANKAMALI_HOG_PATH = os.environ["ANKAMALI_HOG_PATH"]
GOTTINGEN_HOG_PATH = os.environ["GOTTINGEN_HOG_PATH"]
INSIGHTS_ACCT_ID = os.environ["INSIGHTS_ACCT_ID"]

search_query = 'updatedDate >= startOfDay()'
# search_query = 'updatedDate >= "2020-04-16 16:00"'
start_num=0
url = f"{JIRA_URL}rest/api/2/search?jql={search_query}&startAt={start_num}"
tempdir = tempfile.gettempdir()
issues = []
r = requests.get(url, auth=(JIRA_USERNAME, JIRA_PASSWORD))
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
    url = f"{JIRA_URL}rest/api/2/search?jql={search_query}&startAt={start_num}"
    r = requests.get(url, auth=(JIRA_USERNAME, JIRA_PASSWORD))
    result = r.json()
    issues.extend(result['issues'])

gdoc_re = re.compile(r'https://docs.google.com/[^\s|\]]+', re.IGNORECASE)
links = defaultdict(set)

logging.info("Reading issue descriptions...")
for issue in issues:
    # extract the description
    description = issue['fields']['description']
    if not description:
        continue
    # find any google doc links and add them to our list
    matches = gdoc_re.findall(description)
    for match in matches:
        links[issue['key']].add(match)


logging.info("Retrieving issue comments...")
for issue in issues:
    # hit the JIRA API to retrieve the comments for each issue
    url = f"{JIRA_URL}rest/api/2/issue/{issue['key']}/comment"
    r = requests.get(url, auth=(JIRA_USERNAME, JIRA_PASSWORD))
    comments = r.json().get('comments', [])
    for comment in comments:
        # find any google doc links in the comment and add them to our list (links)
        matches = gdoc_re.findall(comment['body'])
        for match in matches:
            links[issue['key']].add(match)

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

# iterate through each JSON file from choctaw_hog and put the results in Insights
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
                    "eventType": "gdrive_secret_monitor",
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

logging.info("Running gottingen hog on each JIRA issue...")
results = []
for issue in issues:
    filename = os.path.join(tempdir, str(uuid.uuid4()))
    cmdline = [
            GOTTINGEN_HOG_PATH,
            "--outputfile",
            filename,
            "--username",
            JIRA_USERNAME,
            "--password",
            JIRA_PASSWORD,
            "--url",
            JIRA_URL,
            issue['key']
        ]
    logging.info(f"Running gottingen hog: {cmdline}")
    s = subprocess.run(
        cmdline,
        capture_output=True
    )
    logging.debug(f"gottingen hog output: {s.stdout}")
    if s.returncode != 0:
        logging.warning(f"gottingen hog exited with a non-zero status code: {s.stdout} {s.stderr}")
    # TODO: add better error handling here.
    results.append({"results": filename})

logging.info(f"len(results) = {len(results)}")

# iterate through each JSON file from gottingen_hog and put the results in Insights
output_array = []
for result_dict in results:
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
                    "eventType": "jira_secret_monitor",
                    "issue_id": finding["issue_id"],
                    "url": finding["url"],
                    "reason": finding["reason"],
                    "location": finding["location"],
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

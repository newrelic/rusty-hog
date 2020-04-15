#!/usr/bin/env python

# This is a simple script meant to retrieve the latest pypi package (provided through environment variables) and perform a
# Rusty Hog scan on the contents of the download. It will then post the results to Insights.

import os
import gzip
import pprint
import re
import requests
import tempfile
import sys
import subprocess
import json
import logging
import xml.etree.ElementTree as ET

loglevel = "WARNING"
for arg in sys.argv:
    if arg.startswith("--log="):
        loglevel = arg[6:]

numeric_level = getattr(logging, loglevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)
logging.basicConfig(level=numeric_level)

# initialize auth tokens, fail if not present
PYPIPACKAGE_NAME = os.environ["PYPIPACKAGE_NAME"]
INSIGHTS_INSERT_KEY = os.environ["INSIGHTS_INSERT_KEY"]
INSIGHTS_ACCT_ID = os.environ["INSIGHTS_ACCT_ID"]
DUROC_HOG_PATH = os.environ["DUROC_HOG_PATH"]


r = requests.get(f"https://pypi.org/simple/{PYPIPACKAGE_NAME}/")
et_result = ET.fromstring(r.text)
links = []
for link_element in et_result[1]:
    if 'href' in link_element.attrib:
        links.append(link_element.attrib['href'])

url = links[-1]
link_regex = re.compile(f"({PYPIPACKAGE_NAME})-([\d\-\.]+)\.tar\.gz", re.IGNORECASE)
link_regex_match = link_regex.search(url)
(pypi_title, pypi_version) = link_regex_match.groups()

r = requests.get(url)
tempdir = tempfile.gettempdir()
tempfile = os.path.join(tempdir, f"{pypi_title}-{pypi_version}.tar.gz")
f = open(tempfile, "wb")
f.write(r.content)
f.close()

duroc_hog_output = subprocess.run([DUROC_HOG_PATH, '-z', tempfile], capture_output=True, check=True)
json_output = json.loads(duroc_hog_output.stdout)
os.remove(tempfile)

output_array = []
for finding in json_output:
    output_array.append({
        'eventType': "pypi_secret_monitor",
        "reason": finding["reason"],
        "path": finding["path"],
        'url': url,
        'pypi_title': pypi_title,
        'pypi_version': pypi_version
    })

url = "https://insights-collector.newrelic.com/v1/accounts/{INSIGHTS_ACCT_ID}/events"
headers = {
    "Content-Type": "application/json",
    "X-Insert-Key": INSIGHTS_INSERT_KEY,
    "Content-Encoding": "gzip",
}
post = gzip.compress(json.dumps(output_array).encode("utf-8"))
logging.info(f"len(output_array) = {len(output_array)}")
logging.debug(output_array)
logging.info("Submitting data to New Relic Insights...")
r = requests.post(url, data=post, headers=headers)
logging.info(f"insights status code: {r.status_code}")



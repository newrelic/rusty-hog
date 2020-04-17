#!/usr/bin/env python

# This is a simple script meant to retrieve all files from a web server with an HTML directory listing and scan
# the files for secrets using duroc_hog. It will then post the results to Insights.

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
import htmllistparse
import time
from urllib.parse import urljoin

loglevel = "WARNING"
for arg in sys.argv:
    if arg.startswith("--log="):
        loglevel = arg[6:]

numeric_level = getattr(logging, loglevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError("Invalid log level: %s" % loglevel)
logging.basicConfig(level=numeric_level)

# initialize auth tokens, fail if not present
DOWNLOAD_CONFIG_PATH = os.environ["DOWNLOAD_CONFIG_PATH"]
INSIGHTS_INSERT_KEY = os.environ["INSIGHTS_INSERT_KEY"]
INSIGHTS_ACCT_ID = os.environ["INSIGHTS_ACCT_ID"]
DUROC_HOG_PATH = os.environ["DUROC_HOG_PATH"]

# config file format: [ { "url": string, "regex": string, "name": string, "recursive": bool } ... ]
# example: [ { "url":"https://download.newrelic.com/php_agent/release/", "regex":".*\\.tar\\.gz", "name":"PHP Agent", "recursive": false} ]

f_j = open(DOWNLOAD_CONFIG_PATH, "r")
config = json.load(f_j)
output_array = []


def scan_binary(url, file_item, name):
    logging.debug(f"scan_binary({url}, {file_item}, {name}")
    output_array = []
    r = requests.get(url)
    tempdir = tempfile.gettempdir()
    tempfile_path = os.path.join(tempdir, file_item.name)
    f = open(tempfile_path, "wb")
    f.write(r.content)
    f.close()

    duroc_hog_output = subprocess.run(
        [DUROC_HOG_PATH, "-z", tempfile_path], capture_output=True, check=True
    )
    json_output = json.loads(duroc_hog_output.stdout)
    os.remove(tempfile_path)

    for finding in json_output:
        output_array.append(
            {
                "eventType": "htmldirlisting_secret_monitor",
                "reason": finding["reason"],
                "path": finding["path"],
                "url": url,
                "filename": file_item.name,
                "name": name,
            }
        )

    return output_array


def scan_url(url, regex, name, recursive):
    time.sleep(1)
    logging.debug(f"scan_url({url}, {regex}, {name}, {recursive}")
    output_array = []
    try:
        cwd, listing = htmllistparse.fetch_listing(url, timeout=15)
        for file_item in listing:
            if not file_item.size and recursive:
                scan_url(urljoin(url, file_item.name), regex, name)
            elif regex.search(file_item.name):
                file_url = urljoin(config_item["url"], file_item.name)
                output_array.extend(scan_binary(file_url, file_item, name))
    except:
        logging.error(f"htmllistparse.fetch_listing({url}, timeout=15) returned an exception")
    return output_array


for config_item in config:
    output_array.extend(
        scan_url(config_item["url"], re.compile(config_item["regex"]), config_item["name"], config_item["recursive"])
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
logging.info("Submitting data to New Relic Insights...")
r = requests.post(url, data=post, headers=headers)
logging.info(f"insights status code: {r.status_code}")

#

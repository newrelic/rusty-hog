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
import htmllistparse
import time
import urllib.parse
import copy
from datetime import datetime

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


def scan_binary(file_url, content_item, config_item):
    logging.debug(f"scan_binary({file_url}, {content_item}, {config_item}")
    output_array = []
    r = requests.get(file_url)
    tempdir = tempfile.gettempdir()
    filename = os.path.basename(urllib.parse.urlparse(file_url).path)
    tempfile_path = os.path.join(tempdir, filename)
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
                "eventType": "s3weblisting_secret_monitor",
                "reason": finding["reason"],
                "path": finding["path"],
                "url": file_url,
                "filename": filename,
                "name": config_item['name'],
            }
        )

    return output_array


def scan_endpoint(config_item):
    endpoint = config_item['endpoint']
    regex = re.compile(config_item['regex'])
    name = config_item['name']
    recursive = config_item['recursive']
    prefixes = config_item['prefixes']
    after_date = datetime.fromisoformat(config_item['after_date'])
    logging.debug(f"scan_endpoint({config_item}")
    output_array = []
    ns = {'aws': 'http://s3.amazonaws.com/doc/2006-03-01/'}

    for prefix in prefixes:
        url = f"https://{endpoint}.s3.amazonaws.com/?delimiter=/&prefix={prefix}"
        et_root = None
        try:
            et_root = ET.fromstring(requests.get(url).text)
        except:
            logging.error(f"ET.fromstring(requests.get({url}).text) returned an exception")
        for content_item in et_root.findall('aws:Contents', ns):
            # logging.debug(f"content_item: {content_item}")
            # logging.debug(f"content_item.find('aws:Key', ns): {content_item.find('aws:Key', ns)}")
            key = content_item.find('aws:Key', ns).text
            size = int(content_item.find('aws:Size', ns).text)
            modified = datetime.fromisoformat(content_item.find('aws:LastModified', ns).text.replace('Z', '+00:00'))
            if regex.search(key) and size > 0 and modified > after_date:
                file_url = f"https://{endpoint}.s3.amazonaws.com/{key}"
                output_array.extend(scan_binary(file_url, content_item, config_item))
        if recursive:
            new_config_item = copy.deepcopy(config_item)
            new_prefixes = [content_item[0].text for content_item in et_root.findall('aws:CommonPrefixes', ns)]
            if len(new_prefixes) > 0:
                new_config_item['prefixes'] = new_prefixes
                output_array.extend(scan_endpoint(new_config_item))

    return output_array


output_array = [result for config_item in config for result in scan_endpoint(config_item)]

# for config_item in config:
#     output_array.extend(scan_url(config_item))

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

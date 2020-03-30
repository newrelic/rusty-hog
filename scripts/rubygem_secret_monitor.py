#!/usr/bin/env python

# This is a simple script meant to retrieve the latest rubygem (provided through environment variables) and perform a
# Rusty Hog scan on the contents of the download. It will then post the results to Insights.

import os
import feedparser
import gzip
import re
import requests
import tempfile
import sys
import subprocess
import json
import logging

loglevel = "WARNING"
for arg in sys.argv:
    if arg.startswith("--log="):
        loglevel = arg[6:]

numeric_level = getattr(logging, loglevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)
logging.basicConfig(level=numeric_level)

# initialize auth tokens, fail if not present
RUBYGEM_NAME = os.environ["RUBYGEM_NAME"]
INSIGHTS_INSERT_KEY = os.environ["INSIGHTS_INSERT_KEY"]
INSIGHTS_ACCT_ID = os.environ["INSIGHTS_ACCT_ID"]
DUROC_HOG_PATH = os.environ["DUROC_HOG_PATH"]

feed_result = feedparser.parse(f"https://rubygems.org/gems/{RUBYGEM_NAME}/versions.atom")
latest_gem = feed_result['entries'][0]['title']
title_regex = re.compile("(.*)\s+\(([0-9\.]+)\)")
(gem_title, gem_version) = title_regex.match(latest_gem).groups()

url = f"https://rubygems.org/downloads/{gem_title}-{gem_version}.gem"
r = requests.get(url)
tempdir = tempfile.gettempdir()
tempfile = os.path.join(tempdir, f"{gem_title}-{gem_version}.gem")
f = open(tempfile, "wb")
f.write(r.content)
f.close()

duroc_hog_output = subprocess.run([DUROC_HOG_PATH, '-z', tempfile], capture_output=True, check=True)
json_output = json.loads(duroc_hog_output.stdout)
os.remove(tempfile)

output_array = []
for finding in json_output:
    output_array.append({
        'eventType': "rubyagent_secret_monitor",
        "reason": finding["reason"],
        "path": finding["path"],
        'url': url,
        'gem_title': gem_title,
        'gem_version': gem_version
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



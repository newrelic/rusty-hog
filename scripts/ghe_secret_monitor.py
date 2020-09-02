# This is a Python script, re-written based on Douglas Day's work, that performs a scan
# of the last 24 hours of commits for an entire GitHub Enterprise instance. It outputs
# the results to the New Relic Insights product which allows you to create alerts and
# visualizations based on the scanning results. It was designed to be run on an Amazon Linux
# EC2 instance on a nightly basis. You can install it using the following commands:
#
# ```shell script
# cd ~
# mkdir rusty-hog
# wget https://github.com/newrelic/rusty-hog/releases/download/v1.0.5/rustyhogs-musl_darwin_1.0.5.zip
# unzip rustyhogs-musl_darwin_1.0.5.zip -d rusty_hog_1.0.5
# cd rusty_hog_1.0.5
# sudo cp ghe_secret_monitor.service /etc/systemd/system
# sudo vi ghe_secret_monitor.timer # modify each <redacted for git> field
# sudo cp ghe_secret_monitor.timer /etc/systemd/system
# sudo systemctl daemon-reload
# sudo systemctl enable ghe_secret_monitor
# ```
#
# You can then perform a one-time execution of secret_monitor with the command
# `sudo service ghe_secret_monitor start` and examine the results in /var/log/messages

from datetime import datetime, timedelta
from github import Github, GithubException
from multiprocessing import Pool
import gzip
import json
import os
import requests
import subprocess
import tempfile
import uuid
import logging
import sys
import random
import urllib.parse

loglevel = "WARNING"
sample = False
knownbad = None
for arg in sys.argv:
    if arg.startswith("--sample="):
        sample = int(arg[9:])
    if arg.startswith("--log="):
        loglevel = arg[6:]
    if arg.startswith("--knownbad="):
        knownbad = arg[11:]
numeric_level = getattr(logging, loglevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)
logging.basicConfig(level=numeric_level)

# initialize auth tokens, fail if not present
GHE_REPO_TOKEN = os.environ["GHE_REPO_TOKEN"]
INSIGHTS_INSERT_KEY = os.environ["INSIGHTS_INSERT_KEY"]
SSH_KEY_PATH = os.environ["SSH_KEY_PATH"]
INSIGHTS_ACCT_ID = os.environ["INSIGHTS_ACCT_ID"]
GHE_DOMAIN = os.environ["GHE_DOMAIN"]
CHOCTAW_HOG_PATH = os.environ["CHOCTAW_HOG_PATH"]

# initialize GitHub object and list of all repos
logging.info("Trying to authenticate to Github...")
g = Github(base_url=f"https://{GHE_DOMAIN}/api/v3", login_or_token=GHE_REPO_TOKEN, per_page=100)
repos = []
if knownbad:
    repos.append(g.get_repo(knownbad))
else:
    repos = g.get_repos()
if sample:
    logging.info(f"sample size set to {sample}, retrieving list of repos...")
    repos = random.sample(list(repos), sample)

# use the datetime library to get an object representing 48 hours ago
today = datetime.today()
twentyfourhoursago = today - timedelta(hours=24)

# start the first main set of work: translate our list of repo objects to a dict of { git_url : since_commit_hash }
repo_dict = {}
logging.info("Getting a list of all commits since 24 hours ago for each repo...")
for repo in repos:
    commits = []
    try:
        commits = list(repo.get_commits(since=twentyfourhoursago))
    except GithubException as e:
        logging.debug(e)
        continue
    if len(commits) == 0:
        logging.debug("len(commits) == 0")
        continue
    if not repo.ssh_url:
        logging.debug("no SSH URL")
        continue
    logging.info(f"({repo.ssh_url}, {commits[-1].sha}")
    repo_dict[repo.ssh_url] = (commits[-1].sha, repo.html_url)

logging.info("Completed Github API requests...")
repo_dict = dict(
    filter(lambda x: x[1], repo_dict.items())
)  # and filter out key/value pairs with None as a value

logging.info(f"len(repo_dict) = {len(repo_dict)}")

# start the next block of work, run choctaw_hog for each key/value pair in repo_dict, and return a dict containing the
# git url as the key and the filename containing the results as the value
tempdir = tempfile.gettempdir()

logging.info("Starting choctaw hog scan of all commits over the last 24 hours...")
def scan_repo(x):
    filename = os.path.join(tempdir, str(uuid.uuid4()))
    cmdline = [
        CHOCTAW_HOG_PATH,
        "--outputfile",
        filename,
        "--since_commit",
        x[1][0],
        "--sshkeypath",
        SSH_KEY_PATH,
        x[0],
    ]
    logging.info(f"Running choctaw hog: {str(cmdline)}")
    s = subprocess.run(cmdline, capture_output=True)
    logging.info(f"choctaw hog output: {s.stdout} {s.stderr}")
    return {"repo": x[0], "results": filename, "url": x[1][1]}

output = []

# increase this number to the number of cores you have - runs great on a c5n.4xlarge with 14
with Pool(3) as p:
    output.extend(p.map(scan_repo, repo_dict.items()))

logging.info(f"len(output) = {len(output)}")
logging.debug(output)

# the last block of work, iterate through each JSON file from choctaw_hog and put the results in Insights
logging.info("Collecting choctaw hog output into a single python list...")
output_array = []
comment_worthy_reasons = [
    "Amazon AWS Access Key ID",
    "Amazon MWS Auth Token",
    "Slack Token",
    "GitHub",
    "MailChimp API Key",
    "Mailgun API Key",
    "Slack Webhook",
    "New Relic Insights Key (specific)",
    "New Relic Insights Key (vague)",
    "New Relic License Key",
    "New Relic HTTP Auth Headers and API Key",
    "New Relic API Key Service Key (new format)",
    "New Relic APM License Key (new format)",
    "New Relic APM License Key (new format, region-aware)",
    "New Relic REST API Key (new format)",
    "New Relic Admin API Key (new format)",
    "New Relic Insights Insert Key (new format)",
    "New Relic Insights Query Key (new format)",
    "New Relic Synthetics Private Location Key (new format)"
]

for result_dict in output:
    try:
        f = open(result_dict["results"], "r")
    except:
        # TODO: add better error handling here. the file won't exist if we couldn't
        # access the git repo
        logging.warning("failed to open " + result_dict["results"])
        continue

    with f:
        result_list = json.load(f)
        logging.info("Processing choctaw_hog output for Git comments and Insights...")
        for finding in result_list:
            # Part 1: Prep the insights findings
            fileurl = ""
            if finding["new_line_num"] != 0:
                fileurl = f"{result_dict['url']}/blob/{finding['commitHash']}/{finding['path']}#L{finding['new_line_num']}"
            else:
                fileurl = f"{result_dict['url']}/blob/{finding['parent_commit_hash']}/{finding['path']}#L{finding['old_line_num']}"
            output_array.append(
                {
                    "eventType": "ghe_secret_monitor",
                    "commitHash": finding["commitHash"],
                    "reason": finding["reason"],
                    "path": finding["path"],
                    "repo": result_dict["repo"],
                    "url": f"{result_dict['url']}/commit/{finding['commitHash']}/{finding['path']}",
                    "fileurl": fileurl,
                    "old_line_num": finding["old_line_num"],
                    "new_line_num": finding["new_line_num"],
                    "parent_commitHash": finding["parent_commit_hash"]
                }
            )

            # Part 2: Comment on the commit
            if finding["reason"] not in comment_worthy_reasons:
                continue
            repo_name = result_dict["repo"].split(":")[1][:-4]
            r = g.get_repo(repo_name)
            c = r.get_commit(finding["commitHash"])
            author = c.author
            body = (
                f"Hi @{author.login} ! It looks like a secret {finding['reason']} was posted in the file {finding['path']} "
                f"on line {finding['new_line_num']} in this commit. We're trying to reduce sensitive information in "
                "GitHub Enterprise by using the Rusty Hog scanner on all commits going forward."
            )
            logging.info(f"Creating Github comment for {result_dict['repo']} {finding['commitHash']}")
            c.create_comment(body)
            

    os.remove(result_dict["results"])

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

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
for arg in sys.argv:
    if arg.startswith("--sample="):
        sample = int(arg[9:])
    if arg.startswith("--log="):
        loglevel = arg[6:]

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
        for finding in result_list:
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

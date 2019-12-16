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

if len(sys.argv) == 2 and sys.argv[1].startswith("--log="):
    loglevel = sys.argv[1][6:]
else:
    loglevel = "WARNING"

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
g = Github(base_url=f"https://{GHE_DOMAIN}/api/v3", login_or_token=GHE_REPO_TOKEN, per_page=100)
repos = g.get_repos()

# use the datetime library to get an object representing 48 hours ago
today = datetime.today()
twentyfourhoursago = today - timedelta(hours=24)

# start the first main set of work: translate our list of repo objects to a dict of { git_url : since_commit_hash }
repo_dict = {}

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
    repo_dict[repo.ssh_url] = (commits[-1].sha, f"{repo.html_url}/commit/")

repo_dict = dict(
    filter(lambda x: x[1], repo_dict.items())
)  # and filter out key/value pairs with None as a value

logging.info(f"len(repo_dict) = {len(repo_dict)}")

# start the next block of work, run choctaw_hog for each key/value pair in repo_dict, and return a dict containing the
# git url as the key and the filename containing the results as the value
tempdir = tempfile.gettempdir()


def scan_repo(x):
    filename = os.path.join(tempdir, str(uuid.uuid4()))
    s = subprocess.run(
        [
            CHOCTAW_HOG_PATH,
            "--outputfile",
            filename,
            "--since_commit",
            x[1][0],
            "--sshkeypath",
            SSH_KEY_PATH,
            x[0],
        ],
        capture_output=True,
    )
    return {"repo": x[0], "results": filename, "url": x[1][1]}


output = []

# increase this number to the number of cores you have - runs great on a c5n.4xlarge with 14
with Pool(3) as p:
    output.extend(p.map(scan_repo, repo_dict.items()))

logging.info(f"len(output) = {len(output)}")
logging.debug(output)

# the last block of work, iterate through each JSON file from choctaw_hog and put the results in Insights
output_array = []
for result_dict in output:
    try:
        f = open(result_dict["results"], "r")
    except:
        continue

    with f:
        result_list = json.load(f)
        for finding in result_list:
            output_array.append(
                {
                    "eventType": "Secret_Police",
                    "commitHash": finding["commitHash"],
                    "reason": finding["reason"],
                    "path": finding["path"],
                    "repo": result_dict["repo"],
                    "url": result_dict["url"] + finding["commitHash"]
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


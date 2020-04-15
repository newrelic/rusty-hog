# This script takes a Github access token and the name of an organization, and runs Choctaw_hog for each repo
# It runs the scans in a multi-processing pool, and collects the results and writes them to output.csv
# It is meant to be used with false_positives.py
# It requires a single third party library: https://github.com/PyGithub/PyGithub
from github import Github
import subprocess
from multiprocessing import Pool
import json
import tempfile
import uuid
import os
import csv
import sys

g = None

if len(sys.argv) == 3:
    g = Github(base_url=f"https://{sys.argv[2]}/api/v3", login_or_token=os.environ['GITHUB_ACCESS_TOKEN'], per_page=100)
elif len(sys.argv) == 2:
    g = Github(os.environ['GITHUB_ACCESS_TOKEN'])
else:
    sys.exit(1)

repos_to_scan = []
for repo in g.get_organization(sys.argv[1]).get_repos(type="all"):
    repos_to_scan.append(repo)

print(f"Scanning {len(repos_to_scan)} repos...")

tempdir = tempfile.gettempdir()


def f(x):
    filename = os.path.join(tempdir, str(uuid.uuid4()))
    # expects choctaw_hog in your path
    s = subprocess.run(["choctaw_hog", "--outputfile", filename, x.ssh_url],
                       capture_output=True)
    return {"repo": x.name, "results": filename}


output = []

with Pool(4) as p: # increase this number to the number of cores you have - runs great on a c5n.4xlarge with 14
    output.extend(p.map(f, repos_to_scan))

print("Complete! Dumping output to output.csv...")

with open('output.csv', 'w') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Repository', 'reason', 'stringsFound', 'path', 'commit', 'commitHash', 'date'])
    for result in output:
        try:
            with open(result['results'], 'r') as f:
                result_list = json.load(f)
                for finding in result_list:
                    writer.writerow([result['repo'],
                                     finding['reason'],
                                     str(finding['stringsFound']),
                                     finding['path'],
                                     finding['commit'],
                                     finding['commitHash'],
                                     finding['date']])
        except:
            pass
        os.remove(result['results'])

print("Output written to output.csv")

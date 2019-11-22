from github import Github
import subprocess
from multiprocessing import Pool
import json
import tempfile
import uuid
import os
import csv
import sys

g = Github(os.environ['GITHUB_ACCESS_TOKEN'])
repos_to_scan = []
for repo in g.get_organization(sys.argv[1]).get_repos(type="all"):
    repos_to_scan.append(repo)

print(f"Scanning {len(repos_to_scan)} repos...")

tempdir = tempfile.gettempdir()


def f(x):
    filename = os.path.join(tempdir, str(uuid.uuid4()))
    # expects choctaw_hog in your path
    s = subprocess.run(["choctaw_hog", "--outputfile", filename, "--regex", "trufflehog_rules.json", x.ssh_url],
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
                                     result['reason'],
                                     str(finding['stringsFound']),
                                     finding['path'],
                                     finding['commit'],
                                     finding['commitHash'],
                                     finding['date']])
        except:
            pass

print("Output written to output.csv")

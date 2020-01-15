# Rusty Hog Scripts

This is a collection of scripts that act as wrappers around the Rusty Hog binaries.
They provide additional functionality that the New Relic security team uses to monitor
and perform wider scans.

## GHE Secret Monitor

This is a Python script, re-written based on Douglas Day's work, that performs a scan
of the last 24 hours of commits for an entire GitHub Enterprise instance. It outputs
the results to the New Relic Insights product which allows you to create alerts and 
visualizations based on the scanning results. It was designed to be run on an Amazon Linux
EC2 instance on a nightly basis. You can install it using the following commands:

```shell script
cd ~
mkdir rusty-hog
wget https://github.com/newrelic/rusty-hog/releases/download/v0.4.5/rustyhogs-0.4.5.zip
unzip rustyhogs-0.4.5.zip -d rusty-hog
cd rusty-hog
sudo cp ghe_secret_monitor.service /etc/systemd/system
sudo vi ghe_secret_monitor.timer # modify each <redacted for git> field
sudo cp ghe_secret_monitor.timer /etc/systemd/system
sudo systemctl daemon-reload 
sudo systemctl enable ghe_secret_monitor
```

You can then perform a one-time execution of secret_scanner with the command 
`sudo service ghe_secret_monitor start` and examine the results in /var/log/messages

## JIRA Secret Scanner

This is a Python script, also re-written based on Douglas Day's work, that performs a
scan of any Google Docs that were linked in JIRA over the last 24 hours. Essentially 
it runs a JQL query for all tickets modified in the last 24 hours, collects all GDrive 
links from the text and comments of each JIRA ticket, and runs ankamali_hog against each
document. It then collects the results and outputs them to New Relic Insights. You can use 
the same installation method as above, substituting jira_secret_scanner for secret_scanner
in each step.

## gh_org_scanner.py

This script takes a Github access token and the name of an organization, and runs
Choctaw_hog for each repo. It runs the scans in a multi-processing pool, and collects
the results and writes them to output.csv It is meant to be used with false_positives.py
It requires a single third party library: https://github.com/PyGithub/PyGithub

## false_positives.py

This is a simple script meant to filter the results from gh_org_scanner.py using a 
blacklist of words. It outputs the results as output_filtered.csv

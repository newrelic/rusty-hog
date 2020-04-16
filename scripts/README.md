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
wget https://github.com/newrelic/rusty-hog/releases/download/v1.0.4/rustyhogs-musl_darwin_1.0.4.zip
unzip rustyhogs-musl_darwin_1.0.4.zip -d rusty_hog_1.0.4
cd rusty_hog_1.0.4
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

## pypi_secret_monitor.py

This is a simple script meant to retrieve the latest pypi package (provided through environment variables) and perform a
Rusty Hog scan on the contents of the download. It will then post the results to Insights.  You can use 
the same installation method as above, substituting pypi_secret_monitor for secret_scanner
in each step.

You will need to supply 4 environment variables to it:
PYPIPACKAGE_NAME - the name of the pypi package used in the pypi URL, e.g. newrelic for https://pypi.org/project/newrelic/
INSIGHTS_INSERT_KEY - the New Relic Insights Insert API key for results
INSIGHTS_ACCT_ID - the New Relic Insights account number for results
DUROC_HOG_PATH - the path to the duroc hog binary (relative or absolute)

## rubygem_secret_monitor.py

Based on pypi_secret_monitor, this is a simple script meant to retrieve the latest rubygem package (provided through 
environment variables) and perform a Rusty Hog scan on the contents of the download. It will then post the results to 
Insights. You can use the same installation method as above, substituting rubygem_secret_monitor for secret_scanner
in each step.

You will need to supply 4 environment variables to it:
RUBYGEM_NAME - the name of the gem package used in the Rubygem URL, e.g. newrelic_rpm for https://rubygems.org/gems/newrelic_rpm
INSIGHTS_INSERT_KEY - the New Relic Insights Insert API key for results
INSIGHTS_ACCT_ID - the New Relic Insights account number for results
DUROC_HOG_PATH - the path to the duroc hog binary (relative or absolute)

## htmldirlisting_secret_monitor.py

This is a python script meant to perform a Rusty Hog scan for all binaries on a web server that uses the generic
Apache directory listing. It uses the [htmllisting-parser](https://github.com/gumblex/htmllisting-parser) library 
to parse a JSON config file (see the example htmldirlisting_secret_monitor.json file) to determine which URLs are scanned.
It outputs the results in New Relic Insights.

You will need to supply 4 environment variables to it:
DOWNLOAD_CONFIG_PATH - the path to the JSON config file, e.g. scripts/htmldirlisting_secret_monitor.json
INSIGHTS_INSERT_KEY - the New Relic Insights Insert API key for results
INSIGHTS_ACCT_ID - the New Relic Insights account number for results
DUROC_HOG_PATH - the path to the duroc hog binary (relative or absolute)

## s3weblisting_secret_monitor.py

This is a python script meant to perform a Rusty Hog scan for all binaries on a web server that uses the generic
web directory listing for an AWS S3 bucket. It parses the XML output from the AWS S3 server and a JSON config file 
(see the example s3weblisting_secret_monitor.json file) to determine which URLs are scanned.
It outputs the results in New Relic Insights.

You will need to supply 4 environment variables to it:
DOWNLOAD_CONFIG_PATH - the path to the JSON config file, e.g. scripts/s3weblisting_secret_monitor.json
INSIGHTS_INSERT_KEY - the New Relic Insights Insert API key for results
INSIGHTS_ACCT_ID - the New Relic Insights account number for results
DUROC_HOG_PATH - the path to the duroc hog binary (relative or absolute)
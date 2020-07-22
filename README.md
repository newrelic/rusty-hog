# Rusty Hogs
Rusty Hog is a secret scanner built in Rust for performance, and based on TruffleHog which is written
in Python. Rusty Hog provides the following binaries:

* Ankamali Hog: Scans for secrets in a Google doc.
* Berkshire Hog: Scans for secrets in an S3 bucket.
* Choctaw Hog: Scans for secrets in a Git repository.
* Duroc Hog: Scans for secrets in a directory, file, and archive.
* Essex Hog: Scans for secrets in a Confluence wiki page.
* Gottingen Hog: Scans for secrets in a JIRA issue.

## Table of contents
<!-- TOC depthFrom:1 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [Rusty Hogs](#rusty-hogs)
	- [Table of contents](#table-of-contents)
- [Usage](#usage)
	- [How to install](#how-to-install)
	- [How to build](#how-to-build)
	- [How to build on Windows](#how-to-build-on-Windows)
	- [Anakamali Hog (GDoc Scanner) usage](#anakamali-hog-gdoc-scanner-usage)
	- [Berkshire Hog (S3 Scanner - CLI) usage](#berkshire-hog-s3-scanner-cli-usage)
	- [Berkshire Hog (S3 Scanner - Lambda) usage](#berkshire-hog-s3-scanner-lambda-usage)
	- [Choctaw Hog (Git Scanner) usage](#choctaw-hog-git-scanner-usage)
	- [Duroc Hog (file system scanner) usage](#duroc-hog-file-system-scanner-usage)
	- [Gottingen Hog (JIRA scanner) usage](#gottingen-hog-jira-scanner-usage)
    - [Regex JSON file format](#regex-json-file-format)
    - [Allowlist JSON file format](#allowlist-json-file-format)
- [Project information](#project-information)
	- [Open source license](#open-source-license)
	- [Support](#support)
	- [Community](#community)
	- [Issues / enhancement requests](#issues-enhancement-requests)
	- [Contributing](#contributing)
	- [Feature Roadmap](#feature-roadmap)
	- [What does the name mean?](#what-does-the-name-mean)

<!-- /TOC -->

# Usage

This project provides a set of scanners that use regular expressions to try and detect the presence of sensitive
information, such as API keys, passwords, and personal information. It includes a set of regular expressions by
default, but also accepts a JSON object containing your custom regular expressions.

## How to install
Download and unzip the [latest ZIP](https://github.com/newrelic/rusty-hog/releases/)
on the releases tab. Then, run each binary with `-h` to see the usage.

```shell script
wget https://github.com/newrelic/rusty-hog/releases/download/1.0.6/rustyhogs-musl_darwin_1.0.6.zip
unzip rustyhogs-musl_darwin_1.0.6.zip
darwin_releases/choctaw_hog -h
```

## How to build
- Ensure you have [Rust](https://www.rust-lang.org/learn/get-started) installed and on your path.
- Clone this repo, and then run `cargo build --release`. The binaries are located in `target/release`.
- To build and view HTML documents, run ```cargo doc --no-deps --open```.
- To run unit tests, run ```cargo test```.
- To cross-compile Berkshire Hog for the AWS Lambda environment, first install
[cross](https://github.com/rust-embedded/cross). Then run the following commands and upload berkshire_lambda.zip to
your AWS Lambda dashboard:
```shell script
cross build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/berkshire_hog bootstrap
zip -j berkshire_lambda.zip bootstrap
```

## How to build on Windows
You will need to compile static OpenSSL binaries and tell Rust/Cargo where to find them:
```
mkdir \Tools
cd \Tools
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg.exe install openssl:x64-windows-static

$env:OPENSSL_DIR = 'C:\Tools\vcpkg\installed\x64-windows-static'
$env:OPENSSL_STATIC = 'Yes'
[System.Environment]::SetEnvironmentVariable('OPENSSL_DIR', $env:OPENSSL_DIR, [System.EnvironmentVariableTarget]::User)
[System.Environment]::SetEnvironmentVariable('OPENSSL_STATIC', $env:OPENSSL_STATIC, [System.EnvironmentVariableTarget]::User)
```
You can now follow the main build instructions listed above.

## Anakamali Hog (GDoc Scanner) usage
```
USAGE:
    ankamali_hog [FLAGS] [OPTIONS] <GDRIVEID>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --oauthsecret        Path to an OAuth secret file (JSON) ./clientsecret.json by default
        --oauthtoken         Path to an OAuth token storage file ./temp_token by default
        --prettyprint        Outputs the JSON in human readable format
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
        --regex <REGEX>          Sets a custom regex JSON file

ARGS:
    <GDRIVEID>    The ID of the Google drive file you want to scan
```

## Berkshire Hog (S3 Scanner - CLI) usage
```
USAGE:
    berkshire_hog [FLAGS] [OPTIONS] <S3URI> <S3REGION>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Outputs the JSON in human readable format
    -r, --recursive          Recursively scans files under the prefix
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
        --profile <PROFILE>      When using a configuration file, enables a non-default profile
        --regex <REGEX>          Sets a custom regex JSON file

ARGS:
    <S3URI>       The location of a S3 bucket and optional prefix or filename to scan. This must be written in the form
                  s3://mybucket[/prefix_or_file]
    <S3REGION>    Sets the region of the S3 bucket to scan
```


## Berkshire Hog (S3 Scanner - Lambda) usage
Berkshire Hog is currently designed to be used as a Lambda function. This is the basic data flow:
<pre>
    ┌───────────┐              ┌───────┐     ┌────────────────┐     ┌────────────┐
    │ S3 bucket │ ┌────────┐   │       │     │ Berkshire Hog  │     │ S3 bucket  │
    │  (input) ─┼─┤S3 event├──▶│  SQS  │────▶│    (Lambda)    │────▶│  (output)  │
    │           │ └────────┘   │       │     │                │     │            │
    └───────────┘              └───────┘     └────────────────┘     └────────────┘
</pre>

In order to run Berkshire Hog this way, set up the following:
1) Configure the input bucket to send an "event" to SQS for each PUSH/PUT event.
2) Set up the SQS topic to accept events from S3, including IAM permissions.
3) Run Berkshire Hog with IAM access to SQS and S3.

## Choctaw Hog (Git Scanner) usage
```
USAGE:
    choctaw_hog [FLAGS] [OPTIONS] <GITPATH>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Outputs the JSON in human readable format
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (4.5 by default)
        --httpspass <HTTPSPASS>                                    Takes a password for HTTPS-based authentication
        --httpsuser <HTTPSUSER>                                    Takes a username for HTTPS-based authentication
    -o, --outputfile <OUTPUT>                                      Sets the path to write the scanner results to (stdout by default)
        --recent_days <RECENTDAYS>                                 Filters commits to the last number of days (branch agnostic)
    -r, --regex <REGEX>                                            Sets a custom regex JSON file
        --since_commit <SINCECOMMIT>                               Filters commits based on date committed (branch agnostic)
        --sshkeypath <SSHKEYPATH>                                  Takes a path to a private SSH key for git authentication, defaults to ssh-agent
        --sshkeyphrase <SSHKEYPHRASE>                              Takes a passphrase to a private SSH key for git authentication, defaults to none
        --until_commit <UNTILCOMMIT>                               Filters commits based on date committed (branch agnostic)
    -w, --allowlist <ALLOWLIST>                                    Sets a custom ALLOWLIST JSON file

ARGS:
    <GITPATH>    Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)
```

## Duroc Hog (file system scanner) usage
```
USAGE:
    duroc_hog [FLAGS] [OPTIONS] <FSPATH>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --prettyprint        Outputs the JSON in human readable format
        --recursive          Scans all subdirectories underneath the supplied path
    -z, --unzip              Recursively scans archives (ZIP and TAR) in memory (dangerous)
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -o, --outputfile <OUTPUT>      Sets the path to write the scanner results to (stdout by default)
    -r, --regex <REGEX>            Sets a custom regex JSON file
    -w, --allowlist <ALLOWLIST>    Sets a custom allowlist JSON file

ARGS:
    <FSPATH>    Sets the path of the directory or file to scan.
```

## Essex Hog (Confluence scanner) usage
```
USAGE:
    essex_hog [FLAGS] [OPTIONS] <PAGEID> <URL>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Outputs the JSON in human readable format
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
        --authtoken <BEARERTOKEN>    Confluence basic auth bearer token (instead of user & pass)
    -o, --outputfile <OUTPUT>        Sets the path to write the scanner results to (stdout by default)
        --password <PASSWORD>        Confluence password (crafts basic auth header)
        --regex <REGEX>              Sets a custom regex JSON file
        --username <USERNAME>        Confluence username (crafts basic auth header)

ARGS:
    <PAGEID>    The ID (e.g. 1234) of the confluence page you want to scan
    <URL>       Base URL of Confluence instance (e.g. https://newrelic.atlassian.net/)
```

## Gottingen Hog (JIRA scanner) usage
```
Jira secret scanner in Rust.

USAGE:
    gottingen_hog [FLAGS] [OPTIONS] <JIRAID> --password <PASSWORD> --username <USERNAME>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Outputs the JSON in human readable format
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
        --url <JIRAURL>
    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
        --password <PASSWORD>    Jira password (or API token)
        --regex <REGEX>          Sets a custom regex JSON file
        --username <USERNAME>    Jira username

ARGS:
    <JIRAID>    The ID (e.g. PROJECT-123) of the Jira issue you want to scan
```

## Regex JSON file format

The regex option on scanners allows users to provide a path to their own JSON file of regular
expressions that match sensitive material. Any provided file currently will replace, not append to, the default 
regular expressions provided by SecretScanner. The expected format of the file is a single json object. 

The keys should be names for the type of secret each regex entry will detect, as the keys will be used for the reason 
properties output by the scanner.

Each value should be a string containing a valid [https://docs.rs/regex/1.3.9/regex/#syntax](regular expression for Rust) 
that should match the type of secret described by its corresponding key.

As of version 1.0.7, the Rusty Hog engine also supports objects as values for each secret. 
The object can contain all of the following:

- a pattern property with the matching regex expression (mandatory)
- an entropy_filter property with a boolean value to enable entropy scanning for this information (mandatory)
- a threshold property to customize the entropy tolerance on a scale of 0 - 1 (optional, will adjust for old 1-8 format, default 0.6)
- a keyspace property to indicate how many possible values are in the key, e.g. 16 for hex, 64 for base64, 128 for ASCII (optional, default 128)
- a make_ascii_lowercase property to indicate whether Rust should perform .make_ascii_lowercase() on the key before calculating entropy (optional, default false)

The higher the threshold, the more entropy is required in the secret to consider it a match.

An example of this format is here:

```json
{
    "Generic Secret": {
        "pattern": "(?i)secret[\\s[[:punct:]]]{1,4}[0-9a-zA-Z-_]{16,64}[\\s[[:punct:]]]?",
        "entropy_filter": true,
        "threshold": "0.6"
    },
    "Slack Token": { 
        "pattern": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
        "entropy_filter": true,
        "threshold": "0.6",
        "keyspace": "36",
        "make_ascii_lowercase": true
    },
    "Google API Key": {
        "pattern": "AIza[0-9A-Za-z\\-_]{35}",
        "entropy_filter": true
    },
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----"
}
```


As of version 1.0.5, the current default regex JSON used is as follows:

```json
{
  "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
  "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
  "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
  "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
  "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  "Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}",
  "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
  "AWS API Key": "AKIA[0-9A-Z]{16}",
  "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
  "Facebook OAuth": "(?i)facebook[\\s[[:punct:]]]{1,4}[0-9a-f]{32}[\\s[[:punct:]]]?",
  "GitHub": "(?i)(github|access[[:punct:]]token)[\\s[[:punct:]]]{1,4}[0-9a-zA-Z]{35,40}",
  "Generic API Key": "(?i)(api|access)[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}[0-9a-zA-Z\\-_]{16,64}[\\s[[:punct:]]]?",
  "Generic Account API Key": "(?i)account[\\s[[:punct:]]]?api[\\s[[:punct:]]]{1,4}[0-9a-zA-Z\\-_]{16,64}[\\s[[:punct:]]]?",
  "Generic Secret": "(?i)secret[\\s[[:punct:]]]{1,4}[0-9a-zA-Z-_]{16,64}[\\s[[:punct:]]]?",
  "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Cloud Platform OAuth": "(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Drive OAuth": "(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google (GCP) Service-account": "(?i)\"type\": \"service_account\"",
  "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Gmail OAuth": "(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
  "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google YouTube OAuth": "(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U][\\s[[:punct:]]]{1,4}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
  "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
  "Mailgun API Key": "(?i)key-[0-9a-zA-Z]{32}",
  "Credentials in absolute URL": "(?i)((https?|ftp)://)(([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+(:([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+)?@)((([a-z0-9]\\.|[a-z0-9][a-z0-9-]*[a-z0-9]\\.)*[a-z][a-z0-9-]*[a-z0-9]|((\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5])\\.){3}(\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5]))(:\\d+)?)(((/+([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)*(\\?([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)?)?)?",
  "PayPal Braintree Access Token": "(?i)access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
  "Picatic API Key": "(?i)sk_live_[0-9a-z]{32}",
  "Slack Webhook": "(?i)https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
  "Stripe API Key": "(?i)sk_live_[0-9a-zA-Z]{24}",
  "Stripe Restricted API Key": "(?i)rk_live_[0-9a-zA-Z]{24}",
  "Square Access Token": "(?i)sq0atp-[0-9A-Za-z\\-_]{22}",
  "Square OAuth Secret": "(?i)sq0csp-[0-9A-Za-z\\-_]{43}",
  "Twilio API Key": "SK[0-9a-fA-F]{32}",
  "Twitter Access Token": "(?i)twitter[\\s[[:punct:]]]{1,4}[1-9][0-9]+-[0-9a-zA-Z]{40}",
  "Twitter OAuth": "(?i)twitter[\\s[[:punct:]]]{1,4}['|\"]?[0-9a-zA-Z]{35,44}['|\"]?",
  "New Relic Partner & REST API Key": "[\\s[[:punct:]]][A-Fa-f0-9]{47}[\\s[[:punct:]][[:cntrl:]]]",
  "New Relic Mobile Application Token": "[\\s[[:punct:]]][A-Fa-f0-9]{42}[\\s[[:punct:]][[:cntrl:]]]",
  "New Relic Synthetics Private Location": "(?i)minion_private_location_key",
  "New Relic Insights Key (specific)": "(?i)insights[\\s[[:punct:]]]?(key|query|insert)[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,40}\\b",
  "New Relic Insights Key (vague)": "(?i)(query|insert)[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}b[\\w-]{32,40}\\b",
  "New Relic License Key": "(?i)license[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,40}\\b",
  "New Relic Internal API Key": "(?i)nr-internal-api-key",
  "New Relic HTTP Auth Headers and API Key": "(?i)(x|newrelic|nr)-?(admin|partner|account|query|insert|api|license)-?(id|key)[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,47}\\b",
  "New Relic API Key Service Key (new format)": "(?i)NRAK-[A-Z0-9]{27}",
  "New Relic APM License Key (new format)": "(?i)[a-f0-9]{36}NRAL",
  "New Relic APM License Key (new format, region-aware)": "(?i)[a-z]{2}[0-9]{2}xx[a-f0-9]{30}NRAL",
  "New Relic REST API Key (new format)": "(?i)NRRA-[a-f0-9]{42}",
  "New Relic Admin API Key (new format)": "(?i)NRAA-[a-f0-9]{27}",
  "New Relic Insights Insert Key (new format)": "(?i)NRII-[A-Za-z0-9-_]{32}",
  "New Relic Insights Query Key (new format)": "(?i)NRIQ-[A-Za-z0-9-_]{32}",
  "New Relic Synthetics Private Location Key (new format)": "(?i)NRSP-[a-z]{2}[0-9]{2}[a-f0-9]{31}",
  "Email address": "(?i)(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])",
  "New Relic Account IDs in URL": "(newrelic\\.com/)?accounts/\\d{1,10}/",
  "Account ID": "(?i)account[\\s[[:punct:]]]?id[\\s[[:punct:]]]{1,4}\\b[\\d]{1,10}\\b",
  "Salary Information": "(?i)(salary|commission|compensation|pay)([\\s[[:punct:]]](amount|target))?[\\s[[:punct:]]]{1,4}\\d+"
}
```

## Allowlist JSON file format

Some of the scanners provide a allowlist feature. This allows you to specific a allowlist file that identifies exceptions
to each regex pattern that should be excluded from the final output.

The format for this allowlist file should be a single json object. Each key in the allowlist should match a key in the 
regex json, and the value should be an array of strings that are exceptions for that regex pattern. For example:

```json
{
    "Email address": [
        "username@mail.com",
        "admin@mail.com"
    ],
    "New Relic Account IDs in URL": [
        "newrelic.com/accounts/some-unoffensive-account-number",
        "newrelic.com/accounts/an-account-that-doesn't-exist-like-this-one",
    ]
}
```

Be aware that in these are strings, not regex expressions, and the keys for this allowlist have to a key in the regex json.
Keys are case-sensitive.

# Project information
## Open source license

This project is distributed under the [Apache 2 license](LICENSE).

## Support

New Relic has open-sourced this project. This project is provided AS-IS WITHOUT WARRANTY OR SUPPORT, although you can report issues and contribute to the project here on GitHub.

_Please do not report issues with this software to New Relic Global Technical Support._

## Community

New Relic hosts and moderates an online forum where customers can interact with New Relic employees as well as other customers to get help and share best practices. Like all official New Relic open source projects, there's a related Community topic in the New Relic Explorer's Hub. You can find this project's topic/threads here:

https://discuss.newrelic.com/t/rusty-hog-multi-platform-secret-key-scanner/90117

## Issues / enhancement requests

Submit issues and enhancement requests in the [Issues tab of this repository](../../issues). Please search for and review the existing open issues before submitting a new issue.

## Contributing

Contributions are welcome (and if you submit a enhancement request, expect to be invited to contribute it yourself). Please review our [Contributors Guide](CONTRIBUTING.md).

Keep in mind that when you submit your pull request, you'll need to sign the CLA via the click-through using CLA-Assistant. If you'd like to execute our corporate CLA, or if you have any questions, please drop us an email at opensource@newrelic.com.


## Feature Roadmap
- 1.0.7:
    - [ ] Replace whitelist with allowlist
    - [x] Improve email regex to stop extraneous matches (https://github.com/newrelic/rusty-hog/issues/11)
    - [ ] Add documentation around DockerHub and Docker usage
    - [ ] Perform at-compile-time inclusion of the default ruleset which can sit in an external JSON file
    
- 1.1: Enterprise features
    - [ ] Support config files (instead of command line args)
    - [ ] Support environment variables instead of CLI args
    - [ ] Multi-threading
    - [ ] Better context detection and false positive filtering (GitHound, machine learning)
    - [ ] Use Rusoto instead of s3-rust
    - [x] Add JIRA scanner
    - [x] Add file-system & archive scanner
    - [ ] Use Rust features to reduce compilation dependencies?

- 1.2: Integration with larger scripts and UIs
    - [ ] Support Github API for larger org management
        - [ ] Scan all repos for a list of users
        - [x] Scan all repos in an org
    - [ ] Generate a web report or web interface. Support "save state" generation from UI.
    - [ ] Agent/manager model
    - [ ] Scheduler process (blocked by save state support)


## What does the name mean?
TruffleHog is considered the de facto standard / original secret scanner. I have been
building a suite of secret scanning tools for various platforms based on TruffleHog
and needed a naming scheme, so I started at the top of Wikipedia's
[list of pig breeds](https://en.wikipedia.org/wiki/List_of_pig_breeds).
Thus each tool name is a breed of pig starting at "A" and working up.

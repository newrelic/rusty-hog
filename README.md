<p align="center">
  <img src="RustyHogLogo_700x700.png" width=350>
</p>
</br>

# rusty-hog
Rusty Hog is a set of secret scanners built for performance using [Rust-lang](https://www.rust-lang.org/). It is based on [TruffleHog](https://github.com/trufflesecurity/trufflehog).

The secret scanners use regular expressions to detect the presence of sensitive information, such as API keys, passwords and personal information.

Rusty Hog provides a default set of regular expressions for secret scanning, but also accepts a JSON object which contains custom regular expressions.

## Contents
Rusty Hog provides the following binaries:
* Ankamali Hog: Google Docs secret scanner
* Berkshire Hog: S3 bucket secret scanner
* Choctaw Hog: Git repository secret scanner
* Duroc Hog: Filesystem (directory, file and archive) secret scanner
* Essex Hog: Confluence wiki page secret scanner
* Gottingen Hog: JIRA issue secret scanner
* Hante Hog: Slack Channel secret scanner

## Table of contents
- Usage
  - [Run via pre-built binaries](#run-via-pre-built-binaries)
  - [Run via Docker](#run-via-docker)
  - [Build instructions](#build-instructions)
  - [Build instructions (lambda)](#build-instructions-lambda)
  - [Build instructions (docs)](#build-instructions-docs)
  - [Testing](#testing)
  - [Linting](#linting)
  - [Ankamali Hog (Google Docs scanner) usage](#ankamali-hog-google-docs-scanner-usage)
  - [Berkshire Hog (S3 scanner - CLI) usage](#berkshire-hog-s3-scanner---cli-usage)
  - [Berkshire Hog (S3 scanner - Lambda) usage](#berkshire-hog-s3-scanner---lambda-usage)
  - [Choctaw Hog (Git scanner) usage](#choctaw-hog-git-scanner-usage)
  - [Duroc Hog (Filesystem scanner) usage](#duroc-hog-filesystem-scanner-usage)
  - [Essex Hog (Confluence scanner) usage](#essex-hog-confluence-scanner-usage)
  - [Gottingen Hog (JIRA scanner) usage](#gottingen-hog-jira-scanner-usage)
  - [Hante Hog (Slack scanner) usage](#hante-hog-slack-scanner-usage)
  - [Regex JSON file format](#regex-json-file-format)
  - [Allowlist JSON file format](#allowlist-json-file-format)
- Project information
  - [Open source license](#open-source-license)
  - [Support](#support)
  - [Community](#community)
  - [Issues / enhancement requests](#issues--enhancement-requests)
  - [Contributing](#contributing)
  - [Feature Roadmap](#feature-roadmap)
  - [What does the name mean?](#what-does-the-name-mean)

## Run via pre-built binaries
Download via `curl`:
```shell script
curl -O https://github.com/newrelic/rusty-hog/releases/download/v1.0.11/rustyhogs-darwin-choctaw_hog-1.0.11.zip
```

Or, download via `wget`:
```shell script
wget https://github.com/newrelic/rusty-hog/releases/download/v1.0.11/rustyhogs-darwin-choctaw_hog-1.0.11.zip
```

Unzip binary and run the help command:
```shell script
unzip rustyhogs-darwin-choctaw_hog-1.0.11.zip
darwin_releases/choctaw_hog -h
```

## Run via Docker
Docker images for Rusty Hog are available through [DockerHub](https://hub.docker.com/u/wetfeet2000).

Download and run choctaw_hog:
```shell script
docker pull wetfeet2000/choctaw_hog
docker run -it --rm wetfeet2000/choctaw_hog --help
```

Hogs can also be downloaded at a specific version (e.g. `v1.0.10`):
```shell script
docker pull wetfeet2000/choctaw_hog:1.0.10
docker run -it --rm wetfeet2000/choctaw_hog:1.0.10 --help
```

## Build instructions
- Install [Rust-lang](https://www.rust-lang.org/learn/get-started)
- Ensure that Rust is defined in your path environment variable

Clone this repository:
```
git clone https://github.com/newrelic/rusty-hog.git
```

Build binary executables:
```shell script
cargo build --release
```

Binary executables are located in `./target/release`

## Build instructions (lambda)
Ensure that you have [Cross](https://github.com/cross-rs/cross) installed:
```shell script
cargo install cross --git https://github.com/cross-rs/cross
```

Cross-compile Berkshire Hog for an AWS Lambda environment:
```shell script
cross build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/berkshire_hog_lambda bootstrap
zip berkshire_hog_lambda.zip bootstrap
```

Deploy berkshire_hog_lambda.zip to AWS Lambda.

## Build instructions (docs)
Build and view documentation:
```shell script
cargo doc --no-deps --open
```

## Testing
Run unit tests:
```shell script
cargo test --release
```

## Linting
Automatically format Rust code according to style guidelines:
```shell script
cargo fmt --all
```

Automatically lint Rust code to fix common mistakes:
```shell script
cargo clippy --fix
```

## Ankamali Hog (Google Docs scanner) usage
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
    -a, --allowlist <ALLOWLIST>                                    Sets a custom allowlist JSON file
        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
    -o, --outputfile <OUTPUT>                                      Sets the path to write the scanner results to (stdout by default)

        --regex <REGEX>                                            Sets a custom regex JSON file

ARGS:
    <GDRIVEID>    The ID of the Google drive file you want to scan
```

## Berkshire Hog (S3 scanner - CLI) usage
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
    -a, --allowlist <ALLOWLIST>                                    Sets a custom allowlist JSON file
        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
    -o, --outputfile <OUTPUT>                                      Sets the path to write the scanner results to (stdout by default)

        --profile <PROFILE>                                        When using a configuration file, enables a non-default profile

        --regex <REGEX>                                            Sets a custom regex JSON file

ARGS:
    <S3URI>       The location of a S3 bucket and optional prefix or filename to scan. This must be written in the
                  form s3://mybucket[/prefix_or_file]
    <S3REGION>    Sets the region of the S3 bucket to scan
```


## Berkshire Hog (S3 scanner - Lambda) usage
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

## Choctaw Hog (Git scanner) usage
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
    -a, --allowlist <ALLOWLIST>                                    Sets a custom ALLOWLIST JSON file

ARGS:
    <GITPATH>    Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)
```

## Duroc Hog (Filesystem scanner) usage
```
USAGE:
    duroc_hog [FLAGS] [OPTIONS] <FSPATH>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --norecursive        Disable recursive scanning of all subdirectories underneath the supplied path
        --prettyprint        Outputs the JSON in human readable format
    -z, --unzip              Recursively scans archives (ZIP and TAR) in memory (dangerous)
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -a, --allowlist <ALLOWLIST>                                    Sets a custom allowlist JSON file
        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
    -o, --outputfile <OUTPUT>                                      Sets the path to write the scanner results to (stdout by default)
    -r, --regex <REGEX>                                            Sets a custom regex JSON file

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
    -a, --allowlist <ALLOWLIST>                                    Sets a custom allowlist JSON file
        --authtoken <BEARERTOKEN>                                  Confluence basic auth bearer token (instead of user & pass)

        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
    -o, --outputfile <OUTPUT>                                      Sets the path to write the scanner results to (stdout by default)
        --password <PASSWORD>                                      Confluence password (crafts basic auth header)
        --regex <REGEX>                                            Sets a custom regex JSON file
        --username <USERNAME>                                      Confluence username (crafts basic auth header)

ARGS:
    <PAGEID>    The ID (e.g. 1234) of the confluence page you want to scan
    <URL>       Base URL of Confluence instance (e.g. https://newrelic.atlassian.net/)
```

## Gottingen Hog (JIRA scanner) usage
```
Jira secret scanner in Rust.

USAGE:
    gottingen_hog [FLAGS] [OPTIONS] <JIRAID>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Outputs the JSON in human readable format
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -a, --allowlist <ALLOWLIST>                                    Sets a custom allowlist JSON file
        --authtoken <BEARERTOKEN>                                  Jira basic auth bearer token (instead of user & pass)
        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
        --url <JIRAURL>                                            Base URL of JIRA instance (e.g. https://jira.atlassian.net/)
    -o, --outputfile <OUTPUT>                                      Sets the path to write the scanner results to (stdout by default)
        --password <PASSWORD>                                      Jira password (crafts basic auth header)
        --regex <REGEX>                                            Sets a custom regex JSON file
        --username <USERNAME>                                      Jira username (crafts basic auth header)

ARGS:
    <JIRAID>    The ID (e.g. PROJECT-123) of the Jira issue you want to scan
```

## Hante Hog (Slack scanner) usage
```
Slack secret scanner in Rust.

USAGE:
    hante_hog [FLAGS] [OPTIONS] --authtoken <BEARERTOKEN> --channelid <CHANNELID> --url <SLACKURL>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Outputs the JSON in human readable format
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -a, --allowlist <ALLOWLIST>                                    Sets a custom allowlist JSON file
        --authtoken <BEARERTOKEN>                                  Slack basic auth bearer token
        --channelid <CHANNELID>
            The ID (e.g. C12345) of the Slack channel you want to scan

        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
        --latest <LATEST>                                          End of time range of messages to include in search
        --oldest <OLDEST>                                          Start of time range of messages to include in search
    -o, --outputfile <OUTPUT>
            Sets the path to write the scanner results to (stdout by default)

        --regex <REGEX>                                            Sets a custom regex JSON file
        --url <SLACKURL>
            Base URL of Slack Workspace (e.g. https://[WORKSPACE NAME].slack.com)
```

## Regex JSON file format
The `--regex` option for each scanner allows users to provide the path of a customized JSON file containing regular expressions which match sensitive material.

The provided JSON file will replace, not append to, the default regular expressions.

The expected format of the provided JSON file is a single JSON object.

The keys represent the secret type that each value will detect, defined using Regex. The keys will be used for the reason property, which is output by the scanner.

Each value should be a string containing a valid [regular expression for Rust](https://docs.rs/regex/1.3.9/regex/#syntax), which matches the secret described by its corresponding key.

As of version 1.0.8, the Rusty Hog engine also supports objects as values for each secret.

The object can contain all of the following:
- a pattern property with the matching Regex (mandatory)
- an entropy_filter property with a boolean value to enable entropy scanning for this secret (mandatory)
- a threshold property to customize the entropy tolerance on a scale of 0 - 1 (optional, will adjust for old 1-8 format, default 0.6)
- a keyspace property to indicate how many possible values are in the key, e.g. 16 for hex, 64 for base64, 128 for ASCII (optional, default 128)
- a make_ascii_lowercase property to indicate whether Rust should perform .make_ascii_lowercase() on the key before calculating entropy (optional, default false)

The higher the threshold, the more entropy is required in the secret for it to be considered a match.

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

As of version 1.0.11, the current default regex JSON used is as follows:
```json
{
	"Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
	"RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
	"SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
	"SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
	"PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
	"Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}",
	"Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
	"Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
	"Facebook OAuth": "(?i)facebook[\\s[[:punct:]]]{1,4}[0-9a-f]{32}[\\s[[:punct:]]]?",
	"GitHub": "(?i)(github|access[[:punct:]]token)[\\s[[:punct:]]]{1,4}[0-9a-zA-Z]{35,40}",
	"Generic API Key": {
		"pattern": "(?i)(api|access)[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}[0-9a-zA-Z\\-_]{16,64}[\\s[[:punct:]]]?",
		"entropy_filter": true,
		"threshold": "0.6",
		"keyspace": "guess"
	},
	"Generic Account API Key": {
		"pattern": "(?i)account[\\s[[:punct:]]]?api[\\s[[:punct:]]]{1,4}[0-9a-zA-Z\\-_]{16,64}[\\s[[:punct:]]]?",
		"entropy_filter": true,
		"threshold": "0.6",
		"keyspace": "guess"
	},
	"Generic Secret": {
		"pattern": "(?i)secret[\\s[[:punct:]]]{1,4}[0-9a-zA-Z-_]{16,64}[\\s[[:punct:]]]?",
		"entropy_filter": true,
		"threshold": "0.6",
		"keyspace": "guess"
	},
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
	"Credentials in absolute URL": "(?i)((https?|ftp)://)(([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+(:([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+)@)((([a-z0-9]\\.|[a-z0-9][a-z0-9-]*[a-z0-9]\\.)*[a-z][a-z0-9-]*[a-z0-9]|((\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5])\\.){3}(\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5]))(:\\d+)?)(((/+([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)*(\\?([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)?)?)?",
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
	"Email address": "(?i)\\b(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*)@[a-z0-9][a-z0-9-]+\\.(com|de|cn|net|uk|org|info|nl|eu|ru)([\\W&&[^:/]]|\\A|\\z)",
	"New Relic Account IDs in URL": "(newrelic\\.com/)?accounts/\\d{1,10}/",
	"Account ID": "(?i)account[\\s[[:punct:]]]?id[\\s[[:punct:]]]{1,4}\\b[\\d]{1,10}\\b",
	"Salary Information": "(?i)(salary|commission|compensation|pay)([\\s[[:punct:]]](amount|target))?[\\s[[:punct:]]]{1,4}\\d+"
}
```

## Allowlist JSON file format
You can provide an allowlist to each secret scanner. An allowlist lets you specify a list of regular expressions for each pattern that will be ignored by the secret scanner.

You can also supply an optional list of regular expressions which are evaluated against the file path.

The format for this allowlist file should be a single JSON object.

Each key in the allowlist should match a key in the Regex json. The value can be one of the following:
- An array of strings that are exceptions for that Regex
- An object with at least one key (patterns) and optionally a second key (paths)

In addition, you can specify the `<GLOBAL>` key, which is evaluated against all patterns.

The following is the default allowlist included in all scans:
```json
{
	"Email address": {
		"patterns": [
			"(?i)@newrelic.com",
			"(?i)noreply@",
			"(?i)test@"
		],
		"paths": [
			"(?i)authors",
			"(?i)contributors",
			"(?i)license",
			"(?i)maintainers",
			"(?i)third_party_notices"
		]
	},
	"Credentials in absolute URL": {
		"patterns": [
			"(?i)(https?://)?user:pass(word)?@"
		]
	},
	"New Relic API Key Service Key (new format)": {
		"patterns": [
			"NRAK-123456789ABCDEFGHIJKLMNOPQR"
		]
	},
	"Generic API Key": {
		"patterns": [
			"(?i)sanitizeAPIKeyForLogging"
		]
	},
	"New Relic License Key": {
		"patterns": [
			"(?i)bootstrap_newrelic_admin_license_key",
			"(?i)xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			"(?i)__YOUR_NEW_RELIC_LICENSE_KEY__LICENSE__",
			"(?i)YOUR_NEW_RELIC_APPLICATION_TOKEN"
		]
	},
	"Generic Secret": {
		"patterns": [
			"(?i)secret:NewRelicLicenseKeySecret"
		]
	},
	"<GLOBAL>": [
		"(?i)example",
		"(?i)fake",
		"(?i)replace",
		"(?i)deadbeef",
		"(?i)ABCDEFGHIJKLMNOPQRSTUVWX",
		"1234567890"
	]
}
```

Be aware that the values in this JSON object are strings, not regular expressions.

The keys for this allowlist have to be a key in the Regex JSON.

Keys are case-sensitive.

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
- 1.1: Enterprise features
    - [ ] Support config files (instead of command line args)
    - [ ] Support environment variables instead of CLI args
    - [ ] Multi-threading
    - [ ] Better context detection and false positive filtering (GitHound, machine learning)
    - [ ] Use Rusoto instead of s3-rust
    - [ ] Use Rust features to reduce compilation dependencies?

- 1.2: Integration with larger scripts and UIs
    - [ ] Support Github API for larger org management
        - [ ] Scan all repos for a list of users
        - [x] Scan all repos in an org
    - [ ] Generate a web report or web interface. Support "save state" generation from UI.
    - [ ] Agent/manager model
    - [ ] Scheduler process (blocked by save state support)

## What does the name mean?
[TruffleHog](https://github.com/trufflesecurity/trufflehog) is considered the de facto standard / original secret scanner.

We have built a suite of secret scanning tools for various platforms based on TruffleHog and needed a naming schema.

The naming schema is inspired by the [list of pig breeds](https://en.wikipedia.org/wiki/List_of_pig_breeds) from Wikipedia. Each tool name is a breed of pig starting at "A" and working down alphabetically.

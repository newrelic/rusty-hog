# Rusty Hogs
Rusty Hog is a secret scanner built in Rust for performance, and based on TruffleHog which is written
in Python. Rusty Hog provides the following binaries:

* Ankamali Hog: Scans for secrets in a Google doc.
* Berkshire Hog: Scans for secrets in an S3 bucket.
* Choctaw Hog: Scans for secrets in a Git repository.
* Duroc Hog: Scans for secrets in a directory, file, and archive.
* Gottingen Hog: Scans for secrets in a JIRA issue.

## Table of contents
<!-- TOC depthFrom:1 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [Rusty Hogs](#rusty-hogs)
	- [Table of contents](#table-of-contents)
- [Usage](#usage)
	- [How to install](#how-to-install)
	- [How to build](#how-to-build)
	- [Anakamali Hog (GDoc Scanner) usage](#anakamali-hog-gdoc-scanner-usage)
	- [Berkshire Hog (S3 Scanner - CLI) usage](#berkshire-hog-s3-scanner-cli-usage)
	- [Berkshire Hog (S3 Scanner - Lambda) usage](#berkshire-hog-s3-scanner-lambda-usage)
	- [Choctaw Hog (Git Scanner) usage](#choctaw-hog-git-scanner-usage)
	- [Duroc Hog (file system scanner) usage](#duroc-hog-file-system-scanner-usage)
	- [Gottingen Hog (JIRA scanner) usage](#gottingen-hog-jira-scanner-usage)
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

This project provides a set of scanners that useA regular expressions to try and detect the presence of sensitive
information, such as API keys, passwords, and personal information. It includes a set of regular expressions by
default, but also accepts a JSON object containing your custom regular expressions.

## How to install
Download and unzip the [latest ZIP](https://github.com/newrelic/rusty-hog/releases/)
on the releases tab. Then, run each binary with `-h` to see the usage.

```shell script
wget https://github.com/newrelic/rusty-hog/releases/download/v1.0.4/rustyhogs-musl_darwin_1.0.4.zip
unzip rustyhogs-musl_darwin_1.0.4.zip
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
    -o, --outputfile <OUTPUT>            Sets the path to write the scanner results to (stdout by default)
        --regex <REGEX>                  Sets a custom regex JSON file
        --since_commit <SINCECOMMIT>     Filters commits based on date committed (branch agnostic)
        --until_commit <SINCECOMMIT>     Filters commits based on date committed (branch agnostic)
        --sshkeypath <SSHKEYPATH>        Takes a path to a private SSH key for git authentication; defaults to ssh-agent
        --sshkeyphrase <SSHKEYPHRASE>    Takes a passphrase to a private SSH key for git authentication; defaults to
                                         none
        --httpsuser <HTTPSUSER>          Takes a username for HTTPS-based authentication
        --httpspass <HTTPSPASS>          Takes a password for HTTPS-based authentication

ARGS:
    <GITPATH>    Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)
```

## Duroc Hog (file system scanner) usage
```
File system secret scanner in Rust

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
    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
    -r, --regex <REGEX>          Sets a custom regex JSON file

ARGS:
    <FSPATH>    Sets the path of the directory or file to scan.
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
- 1.1: Enterprise features
    - [ ] Support config files (instead of command line args)
    - [ ] Support environment variables instead of CLI args
    - [ ] Multi-threading
    - [ ] Better context detection and false positive filtering (GitHound, machine learning)
    - [ ] Use Rusoto instead of s3-rust
    - [ ] Add JIRA scanner
    - [ ] Add file-system & archive scanner
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

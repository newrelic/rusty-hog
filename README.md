# Rusty Hogs
A suite of secret scanners built in Rust for performance. Based on [TruffleHog](https://github.com/dxa4481/truffleHog)
which is written in Python.

Ankamali Hog: Scan for secrets in a Google Doc

Berkshire Hog: Scan for secrets in an S3 bucket

Choctaw Hog: Scan for secrets in a Git repository

* [Rusty Hogs](#rusty-hogs)
* [How to run](#how-to-run)
* [How to build](#how-to-build)
* [Anakamali Hog Usage](#anakamali-hog-usage)
* [Berkshire Hog (CLI) Usage](#berkshire-hog-cli-usage)
* [Berkshire Hog (Lambda) Usage](#berkshire-hog-lambda-usage)
* [Choctaw Hog Usage](#choctaw-hog-usage)
* [Open Source License](#open-source-license)
* [Support](#support)
* [Community](#community)
* [Issues / Enhancement Requests](#issues--enhancement-requests)
* [Contributing](#contributing)
* [Feature Roadmap](#feature-roadmap)
* [Performance comparison](#performance-comparison)
* [What does the name mean?](#what-does-the-name-mean)

## How to run
Download and unzip the [latest ZIP](https://github.com/newrelic/rusty-hog/releases/download/v0.4.4/rustyhogs-0.4.4.zip)
on the releases tab, then you can run each binary with `-h` to see the usage.

```shell script
wget https://github.com/newrelic/rusty-hog/releases/download/v0.4.4/rustyhogs-0.4.4.zip
unzip rustyhogs-0.4.4.zip
cd darwin_releases
./choctaw_hog -h
```

## How to build
Ensure you have [Rust](https://www.rust-lang.org/learn/get-started) installed and on your path.

Perform a git clone, then run `cargo build --release`. The binaries will be located in `target/release`

To cross-compile Berkshire Hog for the AWS Lambda environment, first install 
[cross](https://github.com/rust-embedded/cross). Then run the following commands and upload berkshire_lambda.zip:
```shell script
cross build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/berkshire_hog bootstrap
zip -j berkshire_lambda.zip bootstrap
```

To build and view HTML documents run ```cargo doc --no-deps --open```

To run unit-tests run ```cargo test```

## Anakamali Hog Usage
```
USAGE:
    ankamali_hog [FLAGS] [OPTIONS] <GDRIVEID>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Output the JSON in human readable format
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
        --regex <REGEX>          Sets a custom regex JSON file

ARGS:
    <GDRIVEID>    The ID of the google drive file you want to scan
```

## Berkshire Hog (CLI) Usage
```
USAGE:
    berkshire_hog [FLAGS] [OPTIONS] <S3URI> <S3REGION>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Output the JSON in human readable format
    -r, --recursive          Will recursively scan files under the prefix.
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
        --profile <PROFILE>      When using a configuration file, use a non-default profile
        --regex <REGEX>          Sets a custom regex JSON file

ARGS:
    <S3URI>       The location of a S3 bucket and optional prefix or filename to scan. This must be written in the form
                  s3://mybucket[/prefix_or_file]
    <S3REGION>    Sets the region of the S3 bucket to scan.
```


## Berkshire Hog (Lambda) Usage
Berkshire Hog is currently designed to be used as a Lambda function. It was written with this overall data-flow
in mind:
<pre>
    ┌───────────┐              ┌───────┐     ┌────────────────┐     ┌────────────┐
    │ S3 Bucket │ ┌────────┐   │       │     │ Berkshire Hog  │     │ S3 Bucket  │
    │  (input) ─┼─┤S3 Event├──▶│  SQS  │────▶│    (Lambda)    │────▶│  (output)  │
    │           │ └────────┘   │       │     │                │     │            │
    └───────────┘              └───────┘     └────────────────┘     └────────────┘
</pre>

In order to run this you will need to setup the following things:
1) The input bucket must be configured to send an "event" to SQS for each PUSH/PUT event
2) The SQS topic must be setup to accept events from S3, including IAM permissions.
3) Berkshire hog must be running with IAM access to SQS and S3.

## Choctaw Hog Usage
```
USAGE:
    choctaw_hog [FLAGS] [OPTIONS] <GITPATH>

FLAGS:
        --caseinsensitive    Sets the case insensitive flag for all regexes
        --entropy            Enables entropy scanning
        --prettyprint        Output the JSON in human readable format
    -v, --verbose            Sets the level of debugging information
    -h, --help               Prints help information
    -V, --version            Prints version information

OPTIONS:
    -o, --outputfile <OUTPUT>            Sets the path to write the scanner results to (stdout by default)
        --regex <REGEX>                  Sets a custom regex JSON file, defaults to ./trufflehog_rules.json
        --since_commit <SINCECOMMIT>     Filters commits based on date committed (branch agnostic)
        --sshkeypath <SSHKEYPATH>        Takes a path to a private SSH key for git authentication, defaults to ssh-agent
        --sshkeyphrase <SSHKEYPHRASE>    Takes a passphrase to a private SSH key for git authentication, defaults to
                                         none

ARGS:
    <GITPATH>    Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)
```

## Open Source License

This project is distributed under the [Apache 2 license](LICENSE).

## Support

New Relic has open-sourced this project. This project is provided AS-IS WITHOUT WARRANTY OR SUPPORT, although you can report issues and contribute to the project here on GitHub.

_Please do not report issues with this software to New Relic Global Technical Support._

## Community

New Relic hosts and moderates an online forum where customers can interact with New Relic employees as well as other customers to get help and share best practices. Like all official New Relic open source projects, there's a related Community topic in the New Relic Explorer's Hub. You can find this project's topic/threads here:

TODO: Create topic in discuss.newrelic.com and put the link here.

## Issues / Enhancement Requests

Issues and enhancement requests can be submitted in the [Issues tab of this repository](../../issues). Please search for and review the existing open issues before submitting a new issue.

## Contributing

Contributions are welcome (and if you submit a Enhancement Request, expect to be invited to contribute it yourself :grin:). Please review our [Contributors Guide](CONTRIBUTING.md).

Keep in mind that when you submit your pull request, you'll need to sign the CLA via the click-through using CLA-Assistant. If you'd like to execute our corporate CLA, or if you have any questions, please drop us an email at opensource@newrelic.com.


## Feature Roadmap
- 1.0: Initial open-source release
    - [x] Refactor git-agnostic code into a reusable library
    - [x] Implement logging correctly
    - [x] Prep for New Relic Homebrew release
    - [x] Prep for New Relic GitHub release
    - [x] Implement licensing
    - [x] Clear with New Relic open source committee
    - [x] Finish initial implementation of Ankamali Hog and Berkshire Hog CLI
    - [ ] Finish New Relic Open Source checklist
    - [ ] Unit tests
    - [ ] Prep for crates.io release
    - [x] Flatten original Git repo

- 1.1: Enterprise features
    - [ ] Support config files (instead of command line args)
    - [ ] Save state between scans, remember and filter "false positives"
    - [ ] Multi-threading
    - [ ] Better context detection and false positive filtering (GitHound, machine learning)
    - [ ] Support for other modes of use for Berkshire Hog (CLI, lambda without SQS)
    - [ ] Use Rusoto instead of s3-rust

- 1.2: Integration with larger scripts and UIs
    - [ ] Support Github API for larger org management
        - [ ] Scan all repos for a list of users
        - [ ] Scan all repos in an org
    - [ ] Generate a web-report or web-interface. Support "save state" generation from UI.
    - [ ] Agent/manager model
    - [ ] Scheduler process (blocked by save state support)


## Performance comparison
Using this repo as a test: `git clone git@github.com:NathanRomike/dictionary-builder.git`

I ran trufflehog 50 times and saw it take 81 seconds...
```
time ( repeat 50 { trufflehog --rules trufflehog_rules.json --regex --entropy=False ../dictionary-builder/ })

37.67s user 40.56s system 95% cpu 1:21.88 total
```

Then I ran Choctaw Hog 50 times and saw it take 49 seconds...
```
time ( repeat 50 { target/release/choctaw_hog ../dictionary-builder })

46.28s user 1.94s system 98% cpu 48.749 total
```

## What does the name mean?
TruffleHog is considered the de-facto standard / original secret scanner. I have been
building a suite of secret scanning tools for various platforms based on TruffleHog
and needed a naming scheme, so I started at the top of Wikipedia's 
[list of pig breeds](https://en.wikipedia.org/wiki/List_of_pig_breeds). 
Thus each tool name is a breed of pig starting at A and working up.


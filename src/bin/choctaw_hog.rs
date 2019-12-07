//! Git secret scanner in Rust (the original TruffleHog replacement)
//!
//! # Usage
//! ```
//!     choctaw_hog [FLAGS] [OPTIONS] <GITPATH>
//!
//!FLAGS:
//!        --caseinsensitive    Sets the case insensitive flag for all regexes
//!        --entropy            Enables entropy scanning
//!        --prettyprint        Output the JSON in human readable format
//!    -v, --verbose            Sets the level of debugging information
//!    -h, --help               Prints help information
//!    -V, --version            Prints version information
//!
//!OPTIONS:
//!    -o, --outputfile <OUTPUT>            Sets the path to write the scanner results to (stdout by default)
//!        --regex <REGEX>                  Sets a custom regex JSON file, defaults to ./trufflehog_rules.json
//!        --since_commit <SINCECOMMIT>     Filters commits based on date committed (branch agnostic)
//!        --sshkeypath <SSHKEYPATH>        Takes a path to a private SSH key for git authentication, defaults to ssh-agent
//!        --sshkeyphrase <SSHKEYPHRASE>    Takes a passphrase to a private SSH key for git authentication, defaults to
//!                                         none
//!
//!ARGS:
//!    <GITPATH>    Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)
//! ```


#[macro_use]
extern crate clap;

extern crate tempdir;

extern crate chrono;

extern crate encoding;

use clap::ArgMatches;
use log::{self, info};
use simple_error::SimpleError;
use std::str;
use tempdir::TempDir;

use rusty_hogs::git_scanning::{GitScanner};
use rusty_hogs::{SecretScanner, SecretScannerBuilder};

fn main() {
    let matches = clap_app!(choctaw_hog =>
        (version: "0.4.5")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "Git secret scanner in Rust")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file, defaults to ./trufflehog_rules.json")
        (@arg GITPATH: +required "Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Output the JSON in human readable format")
        (@arg SINCECOMMIT: --since_commit +takes_value "Filters commits based on date committed (branch agnostic)")
        (@arg SSHKEYPATH: --sshkeypath +takes_value "Takes a path to a private SSH key for git authentication, defaults to ssh-agent")
        (@arg SSHKEYPHRASE: --sshkeyphrase +takes_value "Takes a passphrase to a private SSH key for git authentication, defaults to none")
    )
    .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => panic!("error: {}", e),
    }
}


fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    // Set logging
    SecretScanner::set_logging(arg_matches.occurrences_of("VERBOSE"));

    // Initialize some more variables
    let secret_scanner = SecretScannerBuilder::new().conf_argm(arg_matches).build();
    let sshkeypath = arg_matches.value_of("SSHKEYPATH");
    let sshkeyphrase = arg_matches.value_of("SSHKEYPHRASE");
    let since_commit = arg_matches.value_of("SINCECOMMIT");
    let scan_entropy = arg_matches.is_present("ENTROPY");
    let prettyprint = arg_matches.is_present("PRETTYPRINT");
    let output_path = arg_matches.value_of("OUTPUT");

    // Get Git objects
    let dest_dir = TempDir::new("rusty_hogs").unwrap();
    let dest_dir_path = dest_dir.path();
    let source_path: &str = arg_matches.value_of("GITPATH").unwrap();

    // Do the scan
    let mut git_scanner = GitScanner::new(secret_scanner).init_git_repo(source_path, &dest_dir_path, sshkeypath, sshkeyphrase);
    let findings = git_scanner.perform_scan(None, since_commit, scan_entropy);

    // Output the results
    info!("Found {} secrets", findings.len());
    SecretScanner::output_findings(&findings, prettyprint, output_path);

    Ok(())
}

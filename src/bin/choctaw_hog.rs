//! Git secret scanner in Rust (the original TruffleHog replacement)
//!
//!
//! # Usage
//! ```
//!     choctaw_hog [FLAGS] [OPTIONS] <GITPATH>
//!
//!FLAGS:
//!        --caseinsensitive    Sets the case insensitive flag for all regexes
//!        --entropy            Enables entropy scanning
//!        --match_entropy      Enable entropy for each pattern match
//!        --prettyprint        Outputs the JSON in human readable format
//!    -v, --verbose            Sets the level of debugging information
//!    -h, --help               Prints help information
//!    -V, --version            Prints version information
//!
//!OPTIONS:
//!        --recent_days <RECENTDAYS>       Filters commits to the last number of days (branch agnostic)
//!        --match_entropy_threshold <MATCH_ENTROPY_THRESHOLD>    Threshold for match entropy (4.5 by default)
//!        --httpspass <HTTPSPASS>          Takes a password for HTTPS-based authentication
//!        --httpsuser <HTTPSUSER>          Takes a username for HTTPS-based authentication
//!    -o, --outputfile <OUTPUT>            Sets the path to write the scanner results to (stdout by default)
//!    -r, --regex <REGEX>                  Sets a custom regex JSON file, defaults to built-in
//!        --since_commit <SINCECOMMIT>     Filters commits based on date committed (branch agnostic)
//!        --sshkeypath <SSHKEYPATH>        Takes a path to a private SSH key for git authentication, defaults to ssh-agent
//!        --sshkeyphrase <SSHKEYPHRASE>    Takes a passphrase to a private SSH key for git authentication, defaults to
//!                                         none
//!        --until_commit <UNTILCOMMIT>     Filters commits based on date committed (branch agnostic)
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
use log::{self, info, error};
use simple_error::SimpleError;
use std::str;
use tempdir::TempDir;

use rusty_hogs::git_scanning::{GitScanner};
use rusty_hogs::{SecretScanner, SecretScannerBuilder};

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
fn main() {
    let matches = clap_app!(choctaw_hog =>
        (version: "1.0.4")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "Git secret scanner in Rust")
        (@arg REGEX: -r --regex +takes_value "Sets a custom regex JSON file")
        (@arg GITPATH: +required "Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg DEFAULT_ENTROPY_THRESHOLD: --default_entropy_threshold +takes_value "Default entropy threshold (4.5 by default)")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Outputs the JSON in human readable format")
        (@arg SINCECOMMIT: --since_commit +takes_value "Filters commits based on date committed (branch agnostic)")
        (@arg UNTILCOMMIT: --until_commit +takes_value "Filters commits based on date committed (branch agnostic)")
        (@arg SSHKEYPATH: --sshkeypath +takes_value "Takes a path to a private SSH key for git authentication, defaults to ssh-agent")
        (@arg SSHKEYPHRASE: --sshkeyphrase +takes_value "Takes a passphrase to a private SSH key for git authentication, defaults to none")
        (@arg HTTPSUSER: --httpsuser +takes_value "Takes a username for HTTPS-based authentication")
        (@arg HTTPSPASS: --httpspass +takes_value "Takes a password for HTTPS-based authentication")
        (@arg RECENTDAYS: --recent_days +takes_value conflicts_with[SINCECOMMIT] "Filters commits to the last number of days (branch agnostic)")
        (@arg WHITELIST: -w --whitelist +takes_value "Sets a custom whitelist JSON file")
    )
    .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => error!( "Error running command: {}", e)
    }
}

/// Main logic contained here. Get the CLI variables, and use them to initialize a GitScanner
fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    // Set logging
    SecretScanner::set_logging(arg_matches.occurrences_of("VERBOSE"));

    // Initialize some more variables
    let secret_scanner = SecretScannerBuilder::new().conf_argm(arg_matches).build();
    let sshkeypath = arg_matches.value_of("SSHKEYPATH");
    let sshkeyphrase = arg_matches.value_of("SSHKEYPHRASE");
    let httpsuser = arg_matches.value_of("HTTPSUSER");
    let httpspass = arg_matches.value_of("HTTPSPASS");
    let since_commit = arg_matches.value_of("SINCECOMMIT");
    let until_commit = arg_matches.value_of("UNTILCOMMIT");
    let scan_entropy = arg_matches.is_present("ENTROPY");
    let recent_days: Option<u32> = match value_t!(arg_matches.value_of("RECENTDAYS"), u32) {
        Ok(d) => { if d == 0 { None } else { Some(d) } },
        Err(_e) => None
    };

    // Get Git objects
    let dest_dir = TempDir::new("rusty_hogs").unwrap();
    let dest_dir_path = dest_dir.path();
    let source_path: &str = arg_matches.value_of("GITPATH").unwrap();

    // Do the scan
    let git_scanner = GitScanner::new_from_scanner(secret_scanner).init_git_repo(
        source_path,
        &dest_dir_path,
        sshkeypath,
        sshkeyphrase,
        httpsuser,
        httpspass,
    );
    let findings = git_scanner.perform_scan(None, since_commit, until_commit, scan_entropy, recent_days) ;

    // Output the results
    info!("Found {} secrets", findings.len());
    match git_scanner.secret_scanner.output_findings(&findings) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with("failed to output findings", SimpleError::new(err.to_string())))
    }
}

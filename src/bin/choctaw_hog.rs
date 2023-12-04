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
//!    -a, --allowlist <allowlist>          Sets a custom allowlist JSON file
//!        --recent_days <RECENTDAYS>       Filters commits to the last number of days (branch agnostic)
//!        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
//!        --httpspass <HTTPSPASS>          Takes a password for HTTPS-based authentication
//!        --httpsuser <HTTPSUSER>          Takes a username for HTTPS-based authentication
//!    -o, --outputfile <OUTPUT>            Sets the path to write the scanner results to (stdout by default)
//!    -r, --regex <REGEX>                  Sets a custom regex JSON file, defaults to built-in
//!        --since_commit <SINCECOMMIT>     Filters commits based on date committed (branch agnostic)
//!        --sshkeypath <SSHKEYPATH>        Takes a path to a private SSH key for git authentication, defaults to ssh-agent
//!        --sshkeyphrase <SSHKEYPHRASE>    Takes a passphrase to a private SSH key for git authentication, defaults to none
//!        --until_commit <UNTILCOMMIT>     Filters commits based on date committed (branch agnostic)
//!
//!ARGS:
//!    <GITPATH>    Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)
//! ```

extern crate clap;

extern crate tempdir;

extern crate chrono;

extern crate encoding;

use clap::{Arg, ArgAction, ArgMatches, Command};
use log::{self, error, info};
use simple_error::SimpleError;
use std::str;
use tempdir::TempDir;

use rusty_hog_scanner::{SecretScanner, SecretScannerBuilder};
use rusty_hogs::git_scanning::GitScanner;

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
fn main() {
    let matches = Command::new("choctaw_hog")
        .version("1.0.11")
        .author("Scott Cutler <scutler@newrelic.com>")
        .about("Git secret scanner in Rust")
        .arg(Arg::new("REGEX").short('r').long("regex").action(ArgAction::Set).value_name("REGEX").help("Sets a custom regex JSON file"))
        .arg(Arg::new("GITPATH").required(true).action(ArgAction::Set).value_name("GIT_PATH").help("Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)"))
        .arg(Arg::new("VERBOSE").short('v').long("verbose").action(ArgAction::Count).help("Sets the level of debugging information"))
        .arg(Arg::new("ENTROPY").long("entropy").action(ArgAction::SetTrue).help("Enables entropy scanning"))
        .arg(Arg::new("DEFAULT_ENTROPY_THRESHOLD").long("default_entropy_threshold").action(ArgAction::Set).default_value("0.6").help("Default entropy threshold (0.6 by default)"))
        .arg(Arg::new("CASE").long("caseinsensitive").action(ArgAction::SetTrue).help("Sets the case insensitive flag for all regexes"))
        .arg(Arg::new("OUTPUT").short('o').long("outputfile").action(ArgAction::Set).help("Sets the path to write the scanner results to (stdout by default)"))
        .arg(Arg::new("PRETTYPRINT").long("prettyprint").action(ArgAction::SetTrue).help("Outputs the JSON in human readable format"))
        .arg(Arg::new("SINCECOMMIT").long("since_commit").action(ArgAction::Set).help("Filters commits based on date committed (branch agnostic)"))
        .arg(Arg::new("UNTILCOMMIT").long("until_commit").action(ArgAction::Set).help("Filters commits based on date committed (branch agnostic)"))
        .arg(Arg::new("SSHKEYPATH").long("sshkeypath").action(ArgAction::Set).help("Takes a path to a private SSH key for git authentication, defaults to ssh-agent"))
        .arg(Arg::new("SSHKEYPHRASE").long("sshkeyphrase").action(ArgAction::Set).help("Takes a passphrase to a private SSH key for git authentication, defaults to none"))
        .arg(Arg::new("HTTPSUSER").long("httpsuser").action(ArgAction::Set).help("Takes a username for HTTPS-based authentication"))
        .arg(Arg::new("HTTPSPASS").long("httpspass").action(ArgAction::Set).help("Takes a password for HTTPS-based authentication"))
        .arg(Arg::new("RECENTDAYS").long("recent_days").action(ArgAction::Set).conflicts_with("SINCECOMMIT").help("Filters commits to the last number of days (branch agnostic)"))
        .arg(Arg::new("ALLOWLIST").short('a').long("allowlist").action(ArgAction::Set).help("Sets a custom allowlist JSON file"))
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => error!("Error running command: {}", e),
    }
}

/// Main logic contained here. Get the CLI variables, and use them to initialize a GitScanner
fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    // Set logging
    SecretScanner::set_logging(arg_matches.get_count("VERBOSE").into());

    // Initialize some more variables
    let secret_scanner = SecretScannerBuilder::new().conf_argm(arg_matches).build();
    let sshkeypath = arg_matches
        .get_one::<String>("SSHKEYPATH")
        .map(|s| s.as_str());
    let sshkeyphrase = arg_matches
        .get_one::<String>("SSHKEYPHRASE")
        .map(|s| s.as_str());
    let httpsuser = arg_matches
        .get_one::<String>("HTTPSUSER")
        .map(|s| s.as_str());
    let httpspass = arg_matches
        .get_one::<String>("HTTPSPASS")
        .map(|s| s.as_str());
    let since_commit = arg_matches
        .get_one::<String>("SINCECOMMIT")
        .map(|s| s.as_str());
    let until_commit = arg_matches
        .get_one::<String>("UNTILCOMMIT")
        .map(|s| s.as_str());
    let recent_days: Option<u32> = match arg_matches.get_one::<u32>("RECENTDAYS") {
        Some(d) => {
            if *d == 0 {
                None
            } else {
                Some(*d)
            }
        }
        None => None,
    };

    // Get Git objects
    let dest_dir = TempDir::new("rusty_hogs").unwrap();
    let dest_dir_path = dest_dir.path();
    let source_path: &str = arg_matches
        .get_one::<String>("GITPATH")
        .map(|s| s.as_str())
        .unwrap();

    // Do the scan
    let git_scanner = GitScanner::new_from_scanner(secret_scanner).init_git_repo(
        source_path,
        &dest_dir_path,
        sshkeypath,
        sshkeyphrase,
        httpsuser,
        httpspass,
    );
    let findings = git_scanner.perform_scan(None, since_commit, until_commit, recent_days);

    // Output the results
    info!("Found {} secrets", findings.len());
    match git_scanner.secret_scanner.output_findings(&findings) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with(
            "failed to output findings",
            SimpleError::new(err.to_string()),
        )),
    }
}

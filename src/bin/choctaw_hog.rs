#[macro_use]
extern crate clap;

extern crate tempdir;

extern crate chrono;

extern crate encoding;

use chrono::NaiveDateTime;

use clap::ArgMatches;
use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use git2::DiffFormat;
use git2::{DiffOptions, Repository, Time};
use log::{self, info};
use regex::bytes::Matches;
use serde::{Deserialize, Serialize};
use simple_error::SimpleError;
use simple_logger;
use simple_logger::init_with_level;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use std::str;
use tempdir::TempDir;
use url::{ParseError, Url};

use rusty_hogs::git_scanning::gitrepo as gitrepo_scanner;
use rusty_hogs::{SecretScanner, SecretScannerBuilder};
use gitrepo_scanner::{GitScanner, GitFinding, GitScheme};

fn main() {
    let matches = clap_app!(choctaw_hog =>
        (version: "0.4.4")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "Git secret hunter in Rust")
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
    match arg_matches.occurrences_of("VERBOSE") {
        0 => init_with_level(log::Level::Warn).unwrap(),
        1 => init_with_level(log::Level::Info).unwrap(),
        2 => init_with_level(log::Level::Debug).unwrap(),
        3 | _ => init_with_level(log::Level::Trace).unwrap(),
    }

    // Initialize some more variables
    let secret_scanner = SecretScannerBuilder::new().conf_argm(arg_matches).build();
    let mut findings: HashSet<GitFinding> = HashSet::new();
    let mut git_scanner: GitScanner = GitScanner::new(secret_scanner);


    // Get Git objects
    let dest_dir = TempDir::new("rusty_hogs").unwrap();
    let dest_dir_path = dest_dir.path();
    let source_path: &str = arg_matches.value_of("GITPATH").unwrap();

    // Do the scan
    git_scanner.init_git_repo(source_path, &dest_dir_path, arg_matches.value_of("SSHKEYPATH"), arg_matches.value_of("SSHKEYPHRASE"));
    git_scanner.perform_scan(None, arg_matches.value_of("SINCECOMMIT"), arg_matches.is_present("ENTROPY"));


    info!("Found {} secrets", findings.len());

    let mut json_text: Vec<u8> = Vec::new();
    if arg_matches.is_present("PRETTYPRINT") {
        json_text.append(serde_json::ser::to_vec_pretty(&findings).unwrap().as_mut());
    } else {
        json_text.append(serde_json::ser::to_vec(&findings).unwrap().as_mut());
    }
    if arg_matches.is_present("OUTPUT") {
        fs::write(arg_matches.value_of("OUTPUT").unwrap(), json_text).unwrap();
    } else {
        println!("{}", str::from_utf8(json_text.as_ref()).unwrap());
    }

    Ok(())
}

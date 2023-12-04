//! S3 secret hunter in Rust. Avoid bandwidth costs, run this within a VPC!
//!
//! # Usage
//! ```text
//! berkshire_hog [FLAGS] [OPTIONS] <S3URI> <S3REGION>
//!
//!FLAGS:
//!        --caseinsensitive    Sets the case insensitive flag for all regexes
//!        --entropy            Enables entropy scanning
//!        --prettyprint        Outputs the JSON in human readable format
//!    -r, --recursive          Recursively scans files under the prefix
//!    -v, --verbose            Sets the level of debugging information
//!    -h, --help               Prints help information
//!    -V, --version            Prints version information
//!
//!OPTIONS:
//!        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
//!    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
//!        --profile <PROFILE>      When using a configuration file, use a non-default profile
//!        --regex <REGEX>          Sets a custom regex JSON file
//!
//!ARGS:
//!    <S3URI>       The location of a S3 bucket and optional prefix or filename to scan. This must be written in the form
//!                  s3://!mybucket[/prefix_or_file]
//!    <S3REGION>    Sets the region of the S3 bucket to scan.
//! ```

extern crate clap;

use clap::{Arg, ArgAction, ArgMatches, Command};
use log::{self, debug, error, info};
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use simple_error::SimpleError;
use simple_error::{require_with, try_with};
use std::str;
use url::Url;

use rusty_hogs::aws_scanning::{S3Finding, S3Scanner};
use rusty_hog_scanner::{SecretScanner, SecretScannerBuilder};
use std::collections::HashSet;

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
fn main() {
    let matches = Command::new("berkshire_hog")
        .version("1.0.11")
        .author("Scott Cutler <scutler@newrelic.com>")
        .about("S3 secret hunter in Rust. Avoid bandwidth costs, run this within a VPC!")
        .arg(Arg::new("REGEX").long("regex").action(ArgAction::Set).help("Sets a custom regex JSON file"))
        .arg(Arg::new("S3URI").required(true).action(ArgAction::Set).help("The location of a S3 bucket and optional prefix or filename to scan. This must be written in the form s3://mybucket[/prefix_or_file]"))
        .arg(Arg::new("S3REGION").required(true).action(ArgAction::Set).help("Sets the region of the S3 bucket to scan"))
        .arg(Arg::new("RECURSIVE").short('r').long("recursive").action(ArgAction::SetTrue).help("Recursively scans files under the prefix"))
        .arg(Arg::new("VERBOSE").short('v').long("verbose").action(ArgAction::Count).help("Sets the level of debugging information"))
        .arg(Arg::new("ENTROPY").long("entropy").action(ArgAction::SetTrue).help("Enables entropy scanning"))
        .arg(Arg::new("DEFAULT_ENTROPY_THRESHOLD").long("default_entropy_threshold").action(ArgAction::Set).default_value("0.6").help("Default entropy threshold (0.6 by default)"))
        .arg(Arg::new("CASE").long("caseinsensitive").action(ArgAction::SetTrue).help("Sets the case insensitive flag for all regexes"))
        .arg(Arg::new("OUTPUT").short('o').long("outputfile").action(ArgAction::Set).help("Sets the path to write the scanner results to (stdout by default)"))
        .arg(Arg::new("PRETTYPRINT").long("prettyprint").action(ArgAction::SetTrue).help("Outputs the JSON in human readable format"))
        .arg(Arg::new("PROFILE").long("profile").action(ArgAction::Set).help("When using a configuration file, enables a non-default profile"))
        .arg(Arg::new("ALLOWLIST").short('a').long("allowlist").action(ArgAction::Set).help("Sets a custom allowlist JSON file"))
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => error!("Error running command: {}", e),
    }
}

/// Main logic contained here. Initialize S3Scanner, parse the URL and objects, then run the scan.
fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    // Set logging
    SecretScanner::set_logging(arg_matches.get_count("VERBOSE").into());

    // Get regex objects
    let ss = SecretScannerBuilder::new().conf_argm(arg_matches).build();
    let s3scanner = S3Scanner::new_from_scanner(ss);

    // Parse the S3URI
    let url: Url = try_with!(
        Url::parse(arg_matches.get_one::<String>("S3URI").unwrap().as_str()),
        "Failed to parse S3URI"
    );
    let bucket_string = require_with!(url.host_str(), "Bucket name not detected in S3 URI");
    debug!("bucket_string: {:?}", bucket_string);
    let key_path = match url.path() {
        "/" => "",
        s => s,
    };

    // Initialize our S3 variables
    let profile = arg_matches.get_one::<String>("PROFILE").map(|s| s.as_str());
    let credentials = Credentials::new(None, None, None, None, profile.as_deref()).unwrap();
    debug!(
        "credentials: {:?} {:?} {:?}",
        credentials.access_key, credentials.secret_key, credentials.security_token
    );
    let region_str = arg_matches.get_one::<String>("S3REGION").unwrap();
    let region: Region = match region_str.parse() {
        Ok(r) => r,
        Err(e) => return Err(SimpleError::new(e.to_string())),
    };
    let bucket: Bucket = match Bucket::new(bucket_string, region, credentials) {
        Ok(r) => r,
        Err(e) => return Err(SimpleError::new(e.to_string())),
    };

    let delimiter = if arg_matches.get_flag("RECURSIVE") {
        None
    } else {
        Some(String::from("/"))
    };

    // Retrieve all the keys that match the prefix
    debug!("key_path: {:?} delimiter: {:?}", key_path, delimiter);
    let results = bucket.list_blocking(String::from(key_path), delimiter);
    let results = match results {
        Ok(r) => r,
        Err(e) => {
            //TODO: This bug has been fixed, need to test it.
            error!(
                "WARNING: There is a bug in rust-s3 library that prevents it from \
                 reading access tokens from .credentials files. If you are using this method, \
                 you will need to export the credentials as environment variables instead. \
                 https://durch.github.io/rust-s3/s3/credentials/struct.Credentials.html"
            );
            return Err(SimpleError::new(format!(
                "Error running AWS list operation: {:?} (failed auth?)",
                e
            )));
        }
    };
    let mut keys: Vec<String> = results
        .into_iter()
        .flat_map(|x| x.0.contents)
        .map(|x| x.key)
        .filter(|x| !x.ends_with('/'))
        .collect();

    // if we didn't find any keys, try accessing the prefix as a file
    if keys.is_empty() {
        keys.push(key_path.to_string());
    }

    // Download and scan each file, generating lots of S3Finding objects
    info!("Scanning {} objects...", keys.len());
    debug!("keys: {:?}", keys);
    let mut findings: Vec<S3Finding> = Vec::new();
    for key in keys {
        let f_result: Result<Vec<S3Finding>, SimpleError> =
            s3scanner.scan_s3_file(bucket.clone(), key.as_ref());
        match f_result {
            Ok(mut f) => findings.append(&mut f),
            Err(_) => error!("Failed to download key {:?}", key),
        };
    }

    // Output the results
    let findings: HashSet<S3Finding> = findings.into_iter().collect();
    info!("Found {} secrets", findings.len());
    match s3scanner.secret_scanner.output_findings(&findings) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with(
            "failed to output findings",
            SimpleError::new(err.to_string()),
        )),
    }
}

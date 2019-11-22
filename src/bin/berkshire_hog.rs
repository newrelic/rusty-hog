#[macro_use]
extern crate clap;

use clap::ArgMatches;
use log::{self, debug, error, info};
use s3::bucket::Bucket;
use s3::credentials::Credentials;
use s3::region::Region;
use secret_scanning::{S3Finding, SecretScanner};
use serde::{Deserialize, Serialize};
use simple_error::SimpleError;
use simple_error::{require_with, try_with};
use simple_logger::init_with_level;
use std::fs;
use std::str;
use url::{Url};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
struct Finding {
    date: String,
    diff: String,
    #[serde(rename = "stringsFound")]
    strings_found: Vec<String>,
    path: String,
    reason: String,
}

fn main() {
    let matches = clap_app!(berkshire_hog =>
        (version: "0.4.4")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "S3 secret hunter in Rust. Avoid bandwidth costs, run this within a VPC!")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file")
        (@arg S3URI: +required "The location of a S3 bucket and optional prefix or file to scan. This must be written in the form s3://mybucket[/prefix_or_file]")
        (@arg S3REGION: +required "Sets the region of the S3 bucket to scan.")
        (@arg RECURSIVE: -r --recursive "Will recursively scan files under the prefix.")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Output the JSON in human readable format")
        (@arg PROFILE: --profile +takes_value "When using a configuration file, use a non-default profile")
//        (@arg AWS_ACCESS_KEY_ID: --awsaccesskeyid +takes_value "Forces manual AWS authentication")
//        (@arg AWS_SECRET_ACCESS_KEY: --awssecretaccesskey +takes_value "Forces manual AWS authentication")
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

    // Get regex objects
    let ss: SecretScanner = match arg_matches.value_of("REGEX") {
        Some(f) => SecretScanner::new_fromfile(f, arg_matches.is_present("CASE"))?,
        None => SecretScanner::new(arg_matches.is_present("CASE"))?,
    };

    // Parse the S3URI
    let url: Url = try_with!(
        Url::parse(arg_matches.value_of("S3URI").unwrap()),
        "Failed to parse S3URI"
    );
    let bucket_string = require_with!(url.host_str(), "Bucket name not detected in S3 URI");
    debug!("bucket_string: {:?}", bucket_string);
    let key_path = match url.path() {
        "/" => "",
        s => s,
    };

    // Initialize our S3 variables
    let profile = arg_matches
        .value_of("PROFILE").and_then(|x| Some(x.to_string()));
    let credentials = Credentials::new(None, None, None, profile);
    debug!(
        "credentials: {:?} {:?} {:?}",
        credentials.access_key, credentials.secret_key, credentials.token
    );
    let region_str = arg_matches.value_of("S3REGION").unwrap();
    let region: Region = match region_str.parse() {
        Ok(r) => r,
        Err(e) => return Err(SimpleError::new(e.to_string())),
    };
    let bucket: Bucket = match Bucket::new(bucket_string, region, credentials.clone()) {
        Ok(r) => r,
        Err(e) => return Err(SimpleError::new(e.to_string())),
    };

    let delimiter = if arg_matches.is_present("RECURSIVE") {
        None
    } else {
        Some(String::from("/"))
    };

    // Retrieve all the keys that match the prefix
    debug!("key_path: {:?} delimiter: {:?}", key_path, delimiter);
    let results = bucket.list_all(String::from(key_path), delimiter);
    let results = match results {
        Ok(r) => r,
        Err(e) => {
            error!("WARNING: There is a bug in rust-s3 library that prevents it from \
            reading access tokens from .credentials files. If you are using this method, \
            you will need to export the credentials as environment variables instead. \
            https://durch.github.io/rust-s3/s3/credentials/struct.Credentials.html");
            return Err(SimpleError::new(format!(
                "Error running AWS list operation: {:?} (failed auth?)",
                e
            )))
        }
    };
    let mut keys: Vec<String> = results
        .into_iter()
        .map(|x| x.0.contents)
        .flatten()
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
            ss.scan_s3_file(bucket.clone(), key.as_ref());
        match f_result {
            Ok(mut f) => findings.append(&mut f),
            Err(_) => error!("Failed to download key {:?}", key),
        };
    }

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

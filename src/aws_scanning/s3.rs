use crate::SecretScanner;
use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use hex;
use log::{self, error, info, trace};
use regex::bytes::{Matches, Regex, RegexBuilder};
use s3::bucket::Bucket;
use serde_derive::{Serialize, Deserialize};
use serde_json::{Map, Value};
use simple_error::SimpleError;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::iter::FromIterator;
use std::str;
use clap::ArgMatches;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
/// serde_json object that represents a single found secret - finding
pub struct S3Finding {
    pub diff: String,
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub bucket: String,
    pub key: String,
    pub region: String,
    pub reason: String,
}

/// Contains helper functions for performing scans of S3 objects
pub struct S3Scanner {
    pub secret_scanner: SecretScanner
}

/// Acts as a wrapper around a SecretScanner object to provide helper functions for performing
/// scanning against AWS S3 objects. Relies on the [rust-s3](https://github.com/durch/rust-s3)
/// which provides S3 access without the AWS Rusoto library.
impl S3Scanner {

    /// Initialize the SecretScanner object first using the SecretScannerBuilder, then provide
    /// it to this constructor method.
    pub fn new(secret_scanner: SecretScanner) -> S3Scanner {
        S3Scanner { secret_scanner }
    }

    /// Takes an initialized [Bucket](https://durch.github.io/rust-s3/s3/bucket/struct.Bucket.html)
    /// object and an S3 object path in the format `s3://<path>` and returns a list of S3Finding
    /// objects.
    pub fn scan_s3_file(
        &self,
        bucket: Bucket,
        filepath: &str,
    ) -> Result<Vec<S3Finding>, SimpleError> {
        // Initialize our S3 variables
        let mut output: Vec<S3Finding> = Vec::new();

        // Get the actual data from S3
        let (data, code) = match bucket.get_object(filepath) {
            Ok(x) => (x.0, x.1),
            Err(e) => return Err(SimpleError::new(e.to_string())),
        };
        trace!("Code: {}\nData: {:?}", code, data);

        // Main loop - split the data based on newlines, then run get_matches() on each line,
        // then make a list of findings in output
        let lines = data.split(|&x| (x as char) == '\n');
        for new_line in lines {
            let results = self.secret_scanner.get_matches(new_line);
            for (r, matches) in results {
                let mut strings_found: Vec<String> = Vec::new();
                for m in matches {
                    let result = ASCII
                        .decode(&new_line[m.start()..m.end()], DecoderTrap::Ignore)
                        .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap());
                    strings_found.push(result);
                }
                if !strings_found.is_empty() {
                    let new_line_string = ASCII
                        .decode(&new_line, DecoderTrap::Ignore)
                        .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap());
                    output.push(S3Finding {
                        diff: new_line_string,
                        strings_found,
                        bucket: bucket.name.clone(),
                        key: filepath.parse().unwrap(),
                        region: bucket.region.to_string(),
                        reason: r.clone(),
                    });
                }
            }
        }
        Ok(output)
    }
}
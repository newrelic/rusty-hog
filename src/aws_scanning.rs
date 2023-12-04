//! Collection of tools for scanning AWS for secrets. Currently only supports S3.
//!
//! `S3Scanner` acts as a wrapper around a `SecretScanner` object to provide helper functions for
//! performing scanning against AWS S3 objects. Relies on the
//! [rust-s3](https://github.com/durch/rust-s3) library which provides helper functions for
//! accessing S3 objects. Eventually this library should be replaced with the offical Rusoto
//! libraries.
//!
//! # Examples
//!
//! Basic usage requires you to create a `S3Scanner` object...
//!
//! ```
//! use rusty_hog_scanner::SecretScannerBuilder;
//! use rusty_hogs::aws_scanning::S3Scanner;
//! let s3s = S3Scanner::new();
//! ```
//!
//! Alternatively you can build a custom `SecretScanner` object and supply it to the `S3Scanner`
//! contructor...
//!
//! ```
//! use rusty_hog_scanner::SecretScannerBuilder;
//! use rusty_hogs::aws_scanning::S3Scanner;
//! let ss = SecretScannerBuilder::new().set_pretty_print(true).build();
//! let s3s = S3Scanner::new_from_scanner(ss);
//! ```
//!
//! After that, you must first run initialize a
//! [`Bucket`](https://durch.github.io/rust-s3/s3/bucket/struct.Bucket.html), and supply it to
//! `scan_s3_file()` along with a file path. which returns a
//! `Vec` of findings. In this example the string values are contrived.
//!
//! ```no_run
//! use rusty_hog_scanner::SecretScannerBuilder;
//! use rusty_hogs::aws_scanning::{S3Scanner, S3Finding};
//! use s3::region::Region;
//! use s3::creds::Credentials;
//! use s3::bucket::Bucket;
//!
//! let s3s = S3Scanner::new();
//! let bucket_string = "testbucket1";
//! let credentials = Credentials::default().unwrap();
//! let region: Region = Region::UsWest2;
//! let bucket: Bucket = match Bucket::new(bucket_string, region, credentials) {
//! Ok(r) => r,
//! Err(e) => panic!(e)
//! };
//! let results = s3s.scan_s3_file(bucket, "s3://testbucket1/727463.json").unwrap();
//! assert_eq!(results.len(), 0);
//! ```

use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use log::{self, error, trace};
use s3::bucket::Bucket;
use serde_derive::{Deserialize, Serialize};
use simple_error::SimpleError;
use std::str;
use rusty_hog_scanner::SecretScanner;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
/// `serde_json` object that represents a single found secret - finding
pub struct S3Finding {
    pub diff: String,
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub bucket: String,
    pub key: String,
    pub region: String,
    pub reason: String,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// Contains helper functions for performing scans of S3 objects
pub struct S3Scanner {
    pub secret_scanner: SecretScanner,
}

/// Acts as a wrapper around a `SecretScanner` object to provide helper functions for performing
/// scanning against AWS S3 objects. Relies on the [rust-s3](https://github.com/durch/rust-s3)
/// which provides S3 access without the AWS Rusoto library.
impl S3Scanner {
    /// Initialize the SecretScanner object first using the SecretScannerBuilder, then provide
    /// it to this constructor method.
    pub fn new_from_scanner(secret_scanner: SecretScanner) -> Self {
        Self { secret_scanner }
    }

    pub fn new() -> Self {
        Self {
            secret_scanner: SecretScanner::default(),
        }
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
        let (code, data) = match bucket.get_object_blocking(filepath) {
            Ok(x) => (x.status_code(), x.to_vec()),
            Err(e) => return Err(SimpleError::new(e.to_string())),
        };
        trace!("Code: {}\nData: {:?}", code, data);

        // Main loop - split the data based on newlines, then run get_matches() on each line,
        // then make a list of findings in output
        let lines = data.split(|&x| (x as char) == '\n');
        for new_line in lines {
            let results = self.secret_scanner.matches_entropy(new_line);
            for (r, matches) in results {
                let mut strings_found: Vec<String> = Vec::new();
                for m in matches {
                    if m.end() > new_line.len() || m.start() > m.end() {
                        error!("index error: {:?} {:?}", new_line, m);
                    }
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

impl Default for S3Scanner {
    fn default() -> Self {
        Self::new()
    }
}

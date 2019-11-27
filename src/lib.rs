//! # Rusty Hogs
//!
//! Rusty Hogs is a Rust crate to perform secret scanning across various data sources. It is split
//! into two parts:
//! 1. A library - Secret Scanner - that runs a set of regular expressions against a byte array
//! and returns a set of matches
//! 2. A set of binaries - * Hog - that uses the secret scanner library against some data source
//! and outputs a JSON array of findings.
//!
//! ## Using the Secret Scanner Library
//!
//! By initializing the secret scanner with only one argument (case_insensitive), it will
//! use the default regex rules built into the library.
//!
//! ```
//! use rusty_hogs::SecretScanner;
//! let ss = SecretScanner::new(false).unwrap();
//! let mut matches_map = ss.get_matches(b"my email is arst@example.com");
//! assert!(matches_map.contains_key(&String::from("Email address")));
//!
//! let matches = matches_map.remove(&String::from("Email address")).unwrap();
//! let match_obj = matches.into_iter().nth(0).unwrap();
//! assert_eq!(match_obj.start(), 12);
//! assert_eq!(match_obj.end(), 28);
//! ```
//!
//! You can also supply your own regular expressions, as a JSON string in the format
//! { "Name of regular expression" : "Regular expression" , ... }
//!
//! ```
//! use rusty_hogs::SecretScanner;
//! let regex_string = r##"{ "Phone number" : "\\d{3}-?\\d{3}-\\d{4}" }"##;
//! let ss = SecretScanner::new_fromstr(regex_string, false).unwrap();
//! let mut matches_map = ss.get_matches(b"my phone is 555-555-5555");
//! assert!(matches_map.contains_key(&String::from("Phone number")));
//!
//! let matches = matches_map.remove(&String::from("Phone number")).unwrap();
//! let match_obj = matches.into_iter().nth(0).unwrap();
//! assert_eq!(match_obj.start(), 12);
//! assert_eq!(match_obj.end(), 24);
//! ```
//!
//! When using the library you should make sure to properly iterate through each result. A single
//! string may contain more than one finding, and a large data source may have hundreds or thousands
//! of results. Below is the typical iterator usage in each binary:
//! ```
//! use rusty_hogs::SecretScanner;
//! let regex_string = r##"{
//! "Short phone number" : "\\d{3}-?\\d{3}-\\d{4}",
//! "Long phone number" : "\\d{3}-\\d{4}",
//! "Email address" : "\\w+@\\w+\\.\\w+" }"##;
//! let ss = SecretScanner::new_fromstr(regex_string, false).unwrap();
//! let input = b"my phone is 555-555-5555\nmy email is arst@example.com";
//! let input_split = input.split(|x| (*x as char) == '\n');
//! let mut secrets: Vec<String> = Vec::new();
//! for new_line in input_split {
//!     let matches_map = ss.get_matches(&new_line);
//!     for (reason, match_iterator) in matches_map {
//!         for matchobj in match_iterator {
//!             secrets.push(reason.clone());
//!         }
//!     }
//! }
//! assert_eq!(secrets.len(), 3);
//! assert_eq!(secrets.pop().unwrap(), "Email address");
//! ```


use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use hex;
use log::{self, error, info, trace};
use regex::bytes::{Matches, Regex, RegexBuilder};
use s3::bucket::Bucket;
use serde_derive::{Serialize};
use serde_json::{Map, Value};
use simple_error::SimpleError;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::iter::FromIterator;
use std::str;

const DEFAULT_REGEX_JSON: &str = r##"
{
  "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
  "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
  "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
  "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
  "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  "Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}",
  "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
  "AWS API Key": "AKIA[0-9A-Z]{16}",
  "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
  "Facebook OAuth": "(?i)facebook.{0,4}['|\"]?[0-9a-f]{32}['|\"]?",
  "GitHub": "(?i)github.{0,4}[0-9a-zA-Z]{35,40}",
  "Generic API Key": "(?i)(api|access)[_-]?key.{0,4}['|\"]?[0-9a-zA-Z\\-_]{32,64}['|\"]?",
  "Generic Account API Key": "(?i)account[_-]?api.{0,4}['|\"]?[0-9a-zA-Z\\-_]{32,64}['|\"]?",
  "Generic Secret": "(?i)secret.{0,4}['|\"]?[0-9a-zA-Z-_]{32,64}['|\"]?",
  "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Cloud Platform OAuth": "(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Drive OAuth": "(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google (GCP) Service-account": "(?i)\"type\": \"service_account\"",
  "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google Gmail OAuth": "(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
  "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
  "Google YouTube OAuth": "(?i)[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
  "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
  "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
  "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
  "Credentials in absolute URL": "(?i)((https?|ftp)://)(([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+(:([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+)?@)((([a-z0-9]\\.|[a-z0-9][a-z0-9-]*[a-z0-9]\\.)*[a-z][a-z0-9-]*[a-z0-9]|((\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5])\\.){3}(\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5]))(:\\d+)?)(((/+([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)*(\\?([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)?)?)?",
  "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
  "Picatic API Key": "sk_live_[0-9a-z]{32}",
  "Slack Webhook": "(?i)https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
  "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
  "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
  "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
  "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
  "Twilio API Key": "SK[0-9a-fA-F]{32}",
  "Twitter Access Token": "(?i)twitter.{0,4}[1-9][0-9]+-[0-9a-zA-Z]{40}",
  "Twitter OAuth": "(?i)twitter.{0,4}['|\"]?[0-9a-zA-Z]{35,44}['|\"]?",
  "New Relic Partner & REST API Key": "[^\\w./\\-\\+][A-Fa-f0-9]{47}[^\\w./\\-\\+]",
  "New Relic Mobile Application Token": "[^\\w./\\-\\+][A-Fa-f0-9]{42}[^\\w./\\-\\+]",
  "New Relic Synthetics Private Location": "(?i)minion_private_location_key",
  "New Relic Insights Key (specific)": "(?i)insights.{0,4}(key|query|insert).{0,4}\\b[\\w-]{32,40}\\b",
  "New Relic Insights Key (vague)": "(?i)(query|insert).{0,4}key.{0,4}b[\\w-]{32,40}\\b",
  "New Relic License Key": "(?i)license.{0,4}key.{0,4}\\b[\\w-]{32,40}\\b",
  "New Relic Internal API Key": "(?i)nr-internal-api-key",
  "New Relic HTTP Auth Headers and API Key": "(?i)(x|newrelic|nr)-(partner|account|query|insert|api|license)-(id|key).{0,4}\\b[\\w-]{32,47}\\b",
  "Email address": "(?i)(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])",
  "New Relic Account IDs in URL": "(newrelic\\.com/)?accounts/\\d{1,10}/",
  "Account ID": "(?i)account.{0,4}id.{0,4}\\b[\\d]{1,10}\\b"
}
"##;

// from https://docs.rs/crate/base64/0.11.0/source/src/tables.rs
const STANDARD_ENCODE: &[u8; 64] = &[
    65,  // input 0 (0x0) => 'A' (0x41)
    66,  // input 1 (0x1) => 'B' (0x42)
    67,  // input 2 (0x2) => 'C' (0x43)
    68,  // input 3 (0x3) => 'D' (0x44)
    69,  // input 4 (0x4) => 'E' (0x45)
    70,  // input 5 (0x5) => 'F' (0x46)
    71,  // input 6 (0x6) => 'G' (0x47)
    72,  // input 7 (0x7) => 'H' (0x48)
    73,  // input 8 (0x8) => 'I' (0x49)
    74,  // input 9 (0x9) => 'J' (0x4A)
    75,  // input 10 (0xA) => 'K' (0x4B)
    76,  // input 11 (0xB) => 'L' (0x4C)
    77,  // input 12 (0xC) => 'M' (0x4D)
    78,  // input 13 (0xD) => 'N' (0x4E)
    79,  // input 14 (0xE) => 'O' (0x4F)
    80,  // input 15 (0xF) => 'P' (0x50)
    81,  // input 16 (0x10) => 'Q' (0x51)
    82,  // input 17 (0x11) => 'R' (0x52)
    83,  // input 18 (0x12) => 'S' (0x53)
    84,  // input 19 (0x13) => 'T' (0x54)
    85,  // input 20 (0x14) => 'U' (0x55)
    86,  // input 21 (0x15) => 'V' (0x56)
    87,  // input 22 (0x16) => 'W' (0x57)
    88,  // input 23 (0x17) => 'X' (0x58)
    89,  // input 24 (0x18) => 'Y' (0x59)
    90,  // input 25 (0x19) => 'Z' (0x5A)
    97,  // input 26 (0x1A) => 'a' (0x61)
    98,  // input 27 (0x1B) => 'b' (0x62)
    99,  // input 28 (0x1C) => 'c' (0x63)
    100, // input 29 (0x1D) => 'd' (0x64)
    101, // input 30 (0x1E) => 'e' (0x65)
    102, // input 31 (0x1F) => 'f' (0x66)
    103, // input 32 (0x20) => 'g' (0x67)
    104, // input 33 (0x21) => 'h' (0x68)
    105, // input 34 (0x22) => 'i' (0x69)
    106, // input 35 (0x23) => 'j' (0x6A)
    107, // input 36 (0x24) => 'k' (0x6B)
    108, // input 37 (0x25) => 'l' (0x6C)
    109, // input 38 (0x26) => 'm' (0x6D)
    110, // input 39 (0x27) => 'n' (0x6E)
    111, // input 40 (0x28) => 'o' (0x6F)
    112, // input 41 (0x29) => 'p' (0x70)
    113, // input 42 (0x2A) => 'q' (0x71)
    114, // input 43 (0x2B) => 'r' (0x72)
    115, // input 44 (0x2C) => 's' (0x73)
    116, // input 45 (0x2D) => 't' (0x74)
    117, // input 46 (0x2E) => 'u' (0x75)
    118, // input 47 (0x2F) => 'v' (0x76)
    119, // input 48 (0x30) => 'w' (0x77)
    120, // input 49 (0x31) => 'x' (0x78)
    121, // input 50 (0x32) => 'y' (0x79)
    122, // input 51 (0x33) => 'z' (0x7A)
    48,  // input 52 (0x34) => '0' (0x30)
    49,  // input 53 (0x35) => '1' (0x31)
    50,  // input 54 (0x36) => '2' (0x32)
    51,  // input 55 (0x37) => '3' (0x33)
    52,  // input 56 (0x38) => '4' (0x34)
    53,  // input 57 (0x39) => '5' (0x35)
    54,  // input 58 (0x3A) => '6' (0x36)
    55,  // input 59 (0x3B) => '7' (0x37)
    56,  // input 60 (0x3C) => '8' (0x38)
    57,  // input 61 (0x3D) => '9' (0x39)
    43,  // input 62 (0x3E) => '+' (0x2B)
    47,  // input 63 (0x3F) => '/' (0x2F)
];

pub struct SecretScanner {
    pub regex_map: BTreeMap<String, Regex>,
}

#[derive(Serialize, Clone)]
pub struct S3Finding {
    diff: String,
    #[serde(rename = "stringsFound")]
    strings_found: Vec<String>,
    bucket: String,
    key: String,
    region: String,
    reason: String,
}

impl SecretScanner {
    pub fn new(case_insensitive: bool) -> Result<SecretScanner, SimpleError> {
        let json_obj: Map<String, Value> = SecretScanner::get_json_from_str(DEFAULT_REGEX_JSON)?;
        let regex_map = SecretScanner::get_regex_objects(json_obj, case_insensitive);
        Ok(SecretScanner { regex_map })
    }

    pub fn new_fromfile(
        filename: &str,
        case_insensitive: bool,
    ) -> Result<SecretScanner, SimpleError> {
        let json_obj: Map<String, Value> = SecretScanner::get_json_from_file(filename)?;
        let regex_map = SecretScanner::get_regex_objects(json_obj, case_insensitive);
        Ok(SecretScanner { regex_map })
    }

    pub fn new_fromstr(input: &str, case_insensitive: bool) -> Result<SecretScanner, SimpleError> {
        let json_obj: Map<String, Value> = SecretScanner::get_json_from_str(input)?;
        let regex_map = SecretScanner::get_regex_objects(json_obj, case_insensitive);
        Ok(SecretScanner { regex_map })
    }

    fn get_json_from_file(filename: &str) -> Result<Map<String, Value>, SimpleError> {
        // Get regexes from JSON
        info!("Attempting to read JSON regex file from {:?}", filename);
        let regexes_filein = File::open(filename);
        let f = match regexes_filein {
            Ok(file) => file,
            Err(e) => return Err(SimpleError::with("Failed to open the JSON regex file", e)),
        };
        let reader = BufReader::new(f);
        info!("Attempting to parse JSON regex file from {:?}", filename);
        match serde_json::from_reader(reader) {
            Ok(m) => Ok(m),
            Err(e) => Err(SimpleError::with("Failed to parse regex JSON", e)),
        }
    }

    fn get_json_from_str(incoming_str: &str) -> Result<Map<String, Value>, SimpleError> {
        info!("Attempting to parse JSON regex file from provided string...");
        match serde_json::from_str(incoming_str) {
            Ok(m) => Ok(m),
            Err(e) => Err(SimpleError::with("Failed to parse regex JSON", e)),
        }
    }

    fn get_regex_objects(
        json_obj: Map<String, Value>,
        case_insensitive: bool,
    ) -> BTreeMap<String, Regex> {
        let regex_map: BTreeMap<String, String> = json_obj
            .into_iter()
            .map(|x| (x.0, String::from(x.1.as_str().unwrap())))
            .collect();

        regex_map
            .into_iter()
            .map(|x| {
                let mut regex_builder = RegexBuilder::new(&x.1);
                regex_builder.size_limit(10_000_000);
                if case_insensitive {
                    regex_builder.case_insensitive(true);
                };
                (x.0, regex_builder.build())
            })
            .inspect(|(_, x)| {
                if let Err(ref e) = x {
                    error!("Error parsing regex string: {:?}", e)
                }
            })
            .filter(|(_, x)| x.is_ok())
            .map(|(k, v)| (k, v.unwrap()))
            .collect()
    }

    // I don't fully understand the lifetimes involved here, so you may have issues
    pub fn get_matches<'a, 'b: 'a>(&'a self, line: &'b [u8]) -> BTreeMap<&'a String, Matches> {
        self.regex_map
            .iter()
            .map(|x| {
                let matches = x.1.find_iter(line);
                (x.0, matches)
            })
            .collect()
    }

    fn is_base64_string(string_in: &[u8]) -> bool {
        let hashset_string_in: HashSet<&u8> = HashSet::from_iter(string_in.iter());
        hashset_string_in.is_subset(&HashSet::from_iter(STANDARD_ENCODE.iter()))
    }

    // from https://docs.rs/crate/entropy/0.3.0/source/src/lib.rs
    fn calc_entropy(bytes: &[u8], keyspace: i32) -> f32 {
        let mut entropy = 0.0;
        let mut counts: HashMap<u8, i32> = HashMap::new();

        for &b in bytes {
            counts.insert(b, counts.get(&b).unwrap_or(&0) + 1);
        }

        for &count in counts.values() {
            let p: f32 = (count as f32) / (keyspace as f32);
            entropy -= p * p.log(2.0);
        }
        //println!("{:?} {}", String::from_utf8(Vec::from(bytes)), entropy);
        entropy
    }

    pub fn get_entropy_findings(line: &[u8]) -> Vec<String> {
        let words: Vec<&[u8]> = line.split(|x| (*x as char) == ' ').collect();
        let words: Vec<&[u8]> = words
            .into_iter()
            .map(|x| {
                std::str::from_utf8(x)
                    .unwrap_or("")
                    .trim_matches(|y: char| {
                        (y == '\'')
                            || (y == '"')
                            || (y == '\r')
                            || (y == '\n')
                            || (y == '(')
                            || (y == ')')
                    })
                    .as_bytes()
            })
            .collect();
        let mut b64_words: Vec<String> = words
            .iter()
            .filter(|word| word.len() >= 20 && SecretScanner::is_base64_string(word))
            .filter(|word| SecretScanner::calc_entropy(word, 64) > 4.5)
            .map(|word| str::from_utf8(word).unwrap().to_string())
            .collect();
        let mut hex_words: Vec<String> = words
            .iter() // there must be a better way
            .filter(|word| (word.len() >= 20) && (word.iter().all(|x| x.is_ascii_hexdigit())))
            .filter_map(|&x| hex::decode(x).ok())
            .filter(|word| SecretScanner::calc_entropy(word, 255) > (3_f32))
            .map(hex::encode)
            .collect();
        let mut output: Vec<String> = Vec::new();
        output.append(&mut b64_words);
        output.append(&mut hex_words);
        output
    }

    // this should be moved to a separate trait to separate base scanning from AWS-related activities
    // and reduce code duplication
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
            let results = self.get_matches(new_line);
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

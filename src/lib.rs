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
//! In order to get a Secret Scanner object you can use the `SecretScannerBuilder`. It uses the
//! Rust builder pattern, and will use the default regex rules without any configuration.
//!
//! ```
//! use rusty_hogs::SecretScannerBuilder;
//! let ss = SecretScannerBuilder::new().build();
//! let mut matches_map = ss.matches(b"my email is arst@example.com");
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
//! use rusty_hogs::SecretScannerBuilder;
//! let regex_string = r##"{ "Phone number" : "\\d{3}-?\\d{3}-\\d{4}" }"##;
//! let ss = SecretScannerBuilder::new().set_json_str(regex_string).build();
//! let mut matches_map = ss.matches(b"my phone is 555-555-5555");
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
//! use rusty_hogs::SecretScannerBuilder;
//! let regex_string = r##"{
//! "Short phone number" : "\\d{3}-?\\d{3}-\\d{4}",
//! "Long phone number" : "\\d{3}-\\d{4}",
//! "Email address" : "\\w+@\\w+\\.\\w+" }"##;
//! let ss = SecretScannerBuilder::new().set_json_str(regex_string).build();
//! let input = b"my phone is 555-555-5555\nmy email is arst@example.com";
//! let input_split = input.split(|x| (*x as char) == '\n');
//! let mut secrets: Vec<String> = Vec::new();
//! for new_line in input_split {
//!     let matches_map = ss.matches(&new_line);
//!     for (reason, match_iterator) in matches_map {
//!         for matchobj in match_iterator {
//!             secrets.push(reason.clone());
//!         }
//!     }
//! }
//! assert_eq!(secrets.len(), 3);
//! assert_eq!(secrets.pop().unwrap(), "Email address");
//! ```

pub mod aws_scanning;
pub mod git_scanning;
pub mod google_scanning;

use clap::ArgMatches;
use hex;
use log::{self, error, info};
use regex::bytes::{Matches, Regex, RegexBuilder};
use serde::Serialize;
use serde_json::{Map,  Value};
use simple_error::SimpleError;
use simple_logger::init_with_level;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::BufReader;
use std::iter::FromIterator;
use std::{fmt, fs, str};
use std::path::Path;
use anyhow::Result;


// Regex in progress:   "Basic Auth": "basic(_auth)?([\\s[[:punct:]]]{1,4}[[[:word:]][[:punct:]]]{8,64}[\\s[[:punct:]]]?){1,2}",

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
  "Facebook OAuth": "(?i)facebook[\\s[[:punct:]]]{1,4}[0-9a-f]{32}[\\s[[:punct:]]]?",
  "GitHub": "(?i)(github|access[[:punct:]]token)[\\s[[:punct:]]]{1,4}[0-9a-zA-Z]{35,40}",
  "Generic API Key": "(?i)(api|access)[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}[0-9a-zA-Z\\-_]{16,64}[\\s[[:punct:]]]?",
  "Generic Account API Key": "(?i)account[\\s[[:punct:]]]?api[\\s[[:punct:]]]{1,4}[0-9a-zA-Z\\-_]{16,64}[\\s[[:punct:]]]?",
  "Generic Secret": "(?i)secret[\\s[[:punct:]]]{1,4}[0-9a-zA-Z-_]{16,64}[\\s[[:punct:]]]?",
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
  "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U][\\s[[:punct:]]]{1,4}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
  "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
  "Mailgun API Key": "(?i)key-[0-9a-zA-Z]{32}",
  "Credentials in absolute URL": "(?i)((https?|ftp)://)(([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+(:([a-z0-9$_\\.\\+!\\*'\\(\\),;\\?&=-]|%[0-9a-f]{2})+)?@)((([a-z0-9]\\.|[a-z0-9][a-z0-9-]*[a-z0-9]\\.)*[a-z][a-z0-9-]*[a-z0-9]|((\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5])\\.){3}(\\d|[1-9]\\d|1\\d{2}|2[0-4][0-9]|25[0-5]))(:\\d+)?)(((/+([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)*(\\?([a-z0-9$_\\.\\+!\\*'\\(\\),;:@&=-]|%[0-9a-f]{2})*)?)?)?",
  "PayPal Braintree Access Token": "(?i)access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
  "Picatic API Key": "(?i)sk_live_[0-9a-z]{32}",
  "Slack Webhook": "(?i)https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
  "Stripe API Key": "(?i)sk_live_[0-9a-zA-Z]{24}",
  "Stripe Restricted API Key": "(?i)rk_live_[0-9a-zA-Z]{24}",
  "Square Access Token": "(?i)sq0atp-[0-9A-Za-z\\-_]{22}",
  "Square OAuth Secret": "(?i)sq0csp-[0-9A-Za-z\\-_]{43}",
  "Twilio API Key": "SK[0-9a-fA-F]{32}",
  "Twitter Access Token": "(?i)twitter[\\s[[:punct:]]]{1,4}[1-9][0-9]+-[0-9a-zA-Z]{40}",
  "Twitter OAuth": "(?i)twitter[\\s[[:punct:]]]{1,4}['|\"]?[0-9a-zA-Z]{35,44}['|\"]?",
  "New Relic Partner & REST API Key": "[\\s[[:punct:]]][A-Fa-f0-9]{47}[\\s[[:punct:]][[:cntrl:]]]",
  "New Relic Mobile Application Token": "[\\s[[:punct:]]][A-Fa-f0-9]{42}[\\s[[:punct:]][[:cntrl:]]]",
  "New Relic Synthetics Private Location": "(?i)minion_private_location_key",
  "New Relic Insights Key (specific)": "(?i)insights[\\s[[:punct:]]]?(key|query|insert)[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,40}\\b",
  "New Relic Insights Key (vague)": "(?i)(query|insert)[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}b[\\w-]{32,40}\\b",
  "New Relic License Key": "(?i)license[\\s[[:punct:]]]?key[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,40}\\b",
  "New Relic Internal API Key": "(?i)nr-internal-api-key",
  "New Relic HTTP Auth Headers and API Key": "(?i)(x|newrelic|nr)-?(admin|partner|account|query|insert|api|license)-?(id|key)[\\s[[:punct:]]]{1,4}\\b[\\w-]{32,47}\\b",
  "New Relic API Key Service Key (new format)": "(?i)NRAK-[A-Z0-9]{27}",
  "New Relic APM License Key (new format)": "(?i)[a-f0-9]{36}NRAL",
  "New Relic APM License Key (new format, region-aware)": "(?i)[a-z]{2}[0-9]{2}xx[a-f0-9]{30}NRAL",
  "New Relic REST API Key (new format)": "(?i)NRRA-[a-f0-9]{42}",
  "New Relic Admin API Key (new format)": "(?i)NRAA-[a-f0-9]{27}",
  "New Relic Insights Insert Key (new format)": "(?i)NRII-[A-Za-z0-9-_]{32}",
  "New Relic Insights Query Key (new format)": "(?i)NRIQ-[A-Za-z0-9-_]{32}",
  "New Relic Synthetics Private Location Key (new format)": "(?i)NRSP-[a-z]{2}[0-9]{2}[a-f0-9]{31}",
  "Email address": "(?i)(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])",
  "New Relic Account IDs in URL": "(newrelic\\.com/)?accounts/\\d{1,10}/",
  "Account ID": "(?i)account[\\s[[:punct:]]]?id[\\s[[:punct:]]]{1,4}\\b[\\d]{1,10}\\b",
  "Salary Information": "(?i)(salary|commission|compensation|pay)([\\s[[:punct:]]](amount|target))?[\\s[[:punct:]]]{1,4}\\d+"
}
"##;

// from https://docs.rs/crate/base64/0.11.0/source/src/tables.rs
// copied because the value itself was private in the base64 crate
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

/// Contains helper functions and the map of regular expressions that are used to find secrets
///
/// The main object that provides the "secret scanning" functionality. The `regex_map` field
/// provides all the regular expressions that the secret scanner will look for.
/// Use `get_matches(line: [u8])` to perform a `regex.find_iter()` for each regular expression in
/// `regex_map`. `get_matches` will return another
/// [`BTreeMap`](https://doc.rust-lang.org/std/collections/struct.BTreeMap.html) where the key is
/// the name of the regular expression and the value is a
/// [`Matches`](https://docs.rs/regex/1.3.1/regex/struct.Matches.html) object.
///
#[derive(Debug, Clone)]
pub struct SecretScanner {
    pub regex_map: BTreeMap<String, Regex>,
    pub whitelist_map: BTreeMap<String, BTreeMap<String, bool>>,
    pub pretty_print: bool,
    pub output_path: Option<String>,
}

/// Used to instantiate the `SecretScanner` object with user-supplied options
///
/// Use the `new()` function to create a builder object, perform configurations as needed, then
/// create the `SecretScanner` object with `.build()`. Each configuration method consumes and returns
/// self so that you can chain them.
///
/// # Examples
///
/// With no configuration you will inherit the default rules that are case sensitive...
/// ```
/// use rusty_hogs::{SecretScannerBuilder, SecretScanner};
/// let ssb: SecretScannerBuilder = SecretScannerBuilder::new();
/// let ss: SecretScanner = ssb.build();
/// assert_ne!(ss.regex_map.len(), 0);
/// ```
///
/// Alternatively, you can supply your own regular expression JSON, and set a global
/// case-insensitive flag...
/// ```
/// use rusty_hogs::{SecretScannerBuilder, SecretScanner};
/// let regex_string = r##"{ "Phone number" : "\\d{3}-?\\d{3}-\\d{4}" }"##;
/// let ssb: SecretScannerBuilder = SecretScannerBuilder::new()
///     .set_json_str(regex_string)
///     .global_case_insensitive(true);
/// assert!(ssb.case_insensitive);
/// let ss: SecretScanner = ssb.build();
/// assert_eq!(ss.regex_map.len(), 1);
/// ```
///
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SecretScannerBuilder {
    pub case_insensitive: bool,
    pub regex_json_str: Option<String>,
    pub regex_json_path: Option<String>,
    pub pretty_print: bool,
    pub output_path: Option<String>,
    pub whitelist_json_path: Option<String>,
}

impl SecretScannerBuilder {
    /// Create a new `SecretScannerBuilder` object with the default config (50 rules, case sensitive)
    pub fn new() -> Self {
        Self {
            case_insensitive: false,
            regex_json_str: None,
            regex_json_path: None,
            pretty_print: false,
            output_path: None,
            whitelist_json_path: None,
        }
    }

    /// Configure multiple values using the clap library's `ArgMatches` object.
    /// This function looks for a "CASE" flag and "REGEX", "WHITELIST" values.
    pub fn conf_argm(mut self, arg_matches: &ArgMatches) -> Self {
        self.case_insensitive = arg_matches.is_present("CASE");
        self.regex_json_path = match arg_matches.value_of("REGEX") {
            Some(s) => Some(String::from(s)),
            None => None,
        };
        self.pretty_print = arg_matches.is_present("PRETTYPRINT");
        self.output_path = match arg_matches.value_of("OUTPUT") {
            Some(s) => Some(String::from(s)),
            None => None,
        };
        self.whitelist_json_path = match arg_matches.value_of("WHITELIST") {
            Some(s) => Some(String::from(s)),
            None => None,
        };
        self
    }

    /// Supply a path to a JSON file on the system that contains regular expressions
    pub fn set_json_path(mut self, json_path: &str) -> Self {
        self.regex_json_path = Some(String::from(json_path));
        self
    }

    /// Supply a string containing a JSON object that contains regular expressions
    pub fn set_json_str(mut self, json_str: &str) -> Self {
        self.regex_json_str = Some(String::from(json_str));
        self
    }

    /// Supply a path to a JSON file on the system that contains whitelists with string
    /// tokens per regular expression
    pub fn set_whitelist_json_path(mut self, whitelist_json_path: &str) -> Self {
        self.whitelist_json_path = Some(String::from(whitelist_json_path));
        self
    }

    /// Force all regular expressions to be case-insensitive, overriding any flags in the regex
    pub fn global_case_insensitive(mut self, case_insensitive: bool) -> Self {
        self.case_insensitive = case_insensitive;
        self
    }

    /// Set output format to pretty printed JSON
    pub fn set_pretty_print(mut self, pretty_print: bool) -> Self {
        self.pretty_print = pretty_print;
        self
    }

    /// Set output path (stdout if set to None)
    pub fn set_output_path(mut self, output_path: &str) -> Self {
        self.output_path = Some(String::from(output_path));
        self
    }

    /// Returns the configured `SecretScanner` object used to perform regex scanning
    pub fn build(&self) -> SecretScanner {
        let json_obj: Result<Map<String, Value>, SimpleError> = match &self.regex_json_path {
            Some(p) => Self::build_json_from_file(&p),
            _ => match &self.regex_json_str {
                Some(s) => Self::build_json_from_str(&s),
                _ => Self::build_json_from_str(DEFAULT_REGEX_JSON),
            },
        };
        let json_obj: Map<String, Value> = match json_obj {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "Error parsing Regex JSON object, falling back to default regex rules: {:?}",
                    e
                );
                Self::build_json_from_str(DEFAULT_REGEX_JSON).unwrap()
            }
        };
        let regex_map = Self::build_regex_objects(json_obj, self.case_insensitive);
        let output_path = match &self.output_path {
            Some(s) => Some(s.clone()),
            None => None,
        };

        let whitelist_map = match &self.whitelist_json_path {
            Some(p) => Self::build_whitelist_from_file(Path::new(p)),
            _ => Ok(BTreeMap::new()),
        };
        let whitelist_map = match whitelist_map {
            Ok(m) => m,
            Err(e) => {
                error!(
                    "Error parsing whitelist JSON object, using an empty whitelist map: {:?}", e
                );
                BTreeMap::new()
            }
        };
        SecretScanner {
            regex_map,
            pretty_print: self.pretty_print,
            output_path,
            whitelist_map: whitelist_map,
        }
    }

    /// Helper function to parse a JSON file path to `Result<Map<String, Value>, SimpleError>` where
    /// `Value` is a [serde_json Value](https://docs.serde.rs/serde_json/value/enum.Value.html)
    /// object. This has the side-effect of reading the file-system.
    fn build_json_from_file(filename: &str) -> Result<Map<String, Value>, SimpleError> {
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

    /// Helper function to parse a JSON string to `Result<Map<String, Value>, SimpleError>` where
    /// `Value` is a [serde_json Value](https://docs.serde.rs/serde_json/value/enum.Value.html)
    /// object.
    pub fn build_json_from_str(incoming_str: &str) -> Result<Map<String, Value>, SimpleError> {
        info!("Attempting to parse JSON regex file from provided string...");
        match serde_json::from_str(incoming_str) {
            Ok(m) => Ok(m),
            Err(e) => Err(SimpleError::with("Failed to parse regex JSON", e)),
        }
    }

    /// Helper function to convert the `Map<String, Value>` generated in `build_json_from...`
    /// to `BTreeMap<String, Regex>` where the key is our "reason" and Regex is a
    /// [regex::bytes::Regex](https://docs.rs/regex/1.3.3/regex/bytes/struct.Regex.html) object.
    fn build_regex_objects(
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

    fn build_whitelist_from_file(filename: &Path) -> Result<BTreeMap<String, BTreeMap<String, bool>>, SimpleError> {
        info!("Attempting to read JSON whitelist file from {:?}", filename);
        let file = File::open(filename);
        let file = match file {
            Ok(f) => f,
            Err(e) => return Err(SimpleError::with("Failed to open the JSON whitelist file", e)),
        };
        let reader = BufReader::new(file);
        info!("Attempting to parse JSON whitelist file {:?}", filename);
        let whitelist: Map<String, Value> = match serde_json::from_reader(reader) {
            Ok(m) => Ok(m),
            Err(e) => Err(SimpleError::with("Failed to parse whitelist JSON", e)),
        }?;
        whitelist
            .into_iter()
            .map(|(p, list)| {
                match list {
                    Value::Array(v) => {
                        let l = v.into_iter().map(|v| match v {
                            Value::String(s) => s,
                            _ => String::from(""),
                        })
                        .map(|t| (t, true))
                        .collect();
                        Ok((p, l))
                    },
                    _ => Err(SimpleError::new("Invalid whitelist JSON format")),
                }
            })
            .collect()
    }
}

impl SecretScanner {

    /// Helper function to set global logging level
    pub fn set_logging(verbose_level: u64) {
        match verbose_level {
            0 => init_with_level(log::Level::Warn).unwrap(),
            1 => init_with_level(log::Level::Info).unwrap(),
            2 => init_with_level(log::Level::Debug).unwrap(),
            _ => init_with_level(log::Level::Trace).unwrap(),
        }
    }

    /// Scan a byte array for regular expression matches, returns a `BTreeMap` of `Matches` for each
    /// regular expression.
    pub fn matches<'a, 'b: 'a>(&'a self, line: &'b [u8]) -> BTreeMap<&'a String, Matches> {
        self.regex_map
            .iter()
            .map(|x| {
                let matches = x.1.find_iter(line);
                (x.0, matches)
            })
            .collect()
    }

    // Helper function to determine whether a byte array only contains valid Base64 characters.
    fn is_base64_string(string_in: &[u8]) -> bool {
        let hashset_string_in: HashSet<&u8> = HashSet::from_iter(string_in.iter());
        hashset_string_in.is_subset(&HashSet::from_iter(STANDARD_ENCODE.iter()))
    }

    // from https://docs.rs/crate/entropy/0.3.0/source/src/lib.rs
    // modified to include the keyspace parameter since we're not calculating against all possible
    // byte values
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

    /// Scan a byte array for arbitrary hex sequences and base64 sequences. Will return a list of
    /// matches for those sequences with a high amount of entropy, potentially indicating a
    /// private key.
    pub fn entropy_findings(line: &[u8]) -> Vec<String> {
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
            .filter(|word| word.len() >= 20 && Self::is_base64_string(word))
            .filter(|word| Self::calc_entropy(word, 64) > 4.5)
            .map(|word| str::from_utf8(word).unwrap().to_string())
            .collect();
        let mut hex_words: Vec<String> = words
            .iter() // there must be a better way
            .filter(|word| (word.len() >= 20) && (word.iter().all(u8::is_ascii_hexdigit)))
            .filter_map(|&x| hex::decode(x).ok())
            .filter(|word| Self::calc_entropy(word, 255) > (3_f32))
            .map(hex::encode)
            .collect();
        let mut output: Vec<String> = Vec::new();
        output.append(&mut b64_words);
        output.append(&mut hex_words);
        output
    }

    /// Helper function that takes a HashSet of serializable structs and outputs them as JSON
    /// Side effect: May write to the file-system based on `self.output_path`
    pub fn output_findings<T: Serialize + Eq + Hash>(&self, findings: &HashSet<T>) -> anyhow::Result<()> {
        let mut json_text: Vec<u8> = Vec::new();
        if self.pretty_print {
            json_text.append(serde_json::ser::to_vec_pretty(findings)?.as_mut());
        } else {
            json_text.append(serde_json::ser::to_vec(findings)?.as_mut());
        }
        match &self.output_path {
            Some(op) => fs::write(op, json_text)?,
            None => println!("{}", str::from_utf8(json_text.as_ref())?),
        };
        Ok(())
    }

    /// Checks if any of the provided tokens is whitelisted
    pub fn is_whitelisted(&self, pattern: &str, tokens: &Vec<String>) -> bool {
        if let Some(whitelist) = self.whitelist_map.get(pattern) {
            for token in tokens {
                if let Some(_) = whitelist.get(token) {
                    return true
                }
            }
        }
        false
    }
}

impl fmt::Display for SecretScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pp = if self.pretty_print { "True" } else { "False" };
        let op = if let Some(p) = self.output_path.as_ref() {
            p
        } else {
            "None"
        };
        write!(
            f,
            "SecretScanner: Regex_map len:{}, Pretty print:{}, Output path:{}",
            self.regex_map.len(),
            pp,
            op
        )
    }
}

impl PartialEq for SecretScanner {
    fn eq(&self, other: &Self) -> bool {
        self.regex_map
            .iter()
            .map(|(k, v)| match other.regex_map.get(k) {
                None => false,
                Some(r) => r.as_str() == v.as_str(),
            })
            .all(|x| x)
            && self.regex_map.keys().eq(other.regex_map.keys())
            && self.pretty_print == other.pretty_print
            && match self.output_path.as_ref() {
                None => other.output_path.is_none(),
                Some(s) => match other.output_path.as_ref() {
                    None => false,
                    Some(t) => *s == *t,
                },
            }
    }
}

impl Eq for SecretScanner {}

impl Hash for SecretScanner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for (k,v) in &self.regex_map {
            k.hash(state);
            v.as_str().hash(state);
        };
        if self.pretty_print {
            "prettyprintyes".hash(state)
        } else {
            "prettyprintno".hash(state)
        }
        match self.output_path.as_ref() {
            None => "outputpathno".hash(state),
            Some(s) => s.hash(state)
        };
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        let ssb = SecretScannerBuilder::new();
        ssb.build()
    }
}

impl Default for SecretScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn can_parse_whitelist_from_file() -> Result<(), String> {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"
        {
            "Pattern name 1": [
                "test1"
            ],
            "Pattern name 2": [
                "test1",
                "test2"
            ]
        }
        "#;
        file.write(json.as_bytes()).unwrap();

        if let Err(e) = SecretScannerBuilder::build_whitelist_from_file(file.path()) {
            return Err(format!("failed parsing valid whitelist JSON file: {}", e));
        }

        Ok(())
    }
}

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

extern crate clap;

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose as Base64Engine};
use clap::ArgMatches;
use log::{self, debug, error, info, LevelFilter};
use regex::bytes::{Match, Matches, Regex, RegexBuilder};
use serde::Serialize;
use serde_derive::Deserialize;
use serde_json::{Map, Value};
use simple_error::SimpleError;
use simple_logger::SimpleLogger;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::BufReader;
use std::ops::Range;
use std::path::Path;
use std::{fmt, fs, str};

// Regex in progress:   "Basic Auth": "basic(_auth)?([\\s[[:punct:]]]{1,4}[[[:word:]][[:punct:]]]{8,64}[\\s[[:punct:]]]?){1,2}",

const DEFAULT_REGEX_JSON: &str = include_str!("default_rules.json");
const DEFAULT_ALLOWLIST_JSON: &str = include_str!("default_allowlist.json");

// from https://docs.rs/crate/base64/0.11.0/source/src/tables.rs
// copied because the value itself was private in the base64 crate
const B64_ENCODE: &[u8; 64] = &[
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

const HEX_ENCODE: &[u8; 22] = &[
    65,  // 'A' (0x41)
    66,  // 'B' (0x42)
    67,  // 'C' (0x43)
    68,  // 'D' (0x44)
    69,  // 'E' (0x45)
    70,  // 'F' (0x46)
    97,  // 'a' (0x61)
    98,  // 'b' (0x62)
    99,  // 'c' (0x63)
    100, // 'd' (0x64)
    101, // 'e' (0x65)
    102, // 'f' (0x66)
    48,  // '0' (0x30)
    49,  // '1' (0x31)
    50,  // '2' (0x32)
    51,  // '3' (0x33)
    52,  // '4' (0x34)
    53,  // '5' (0x35)
    54,  // '6' (0x36)
    55,  // '7' (0x37)
    56,  // '8' (0x38)
    57,  // '9' (0x39)
];

const WORD_SPLIT: &[u8; 8] = &[
    32, // ' '
    34, // '"'
    39, // "'"
    40, // '('
    41, // ')'
    58, // ':'
    61, // '='
    96, // '`'
];

const DEFAULT_ENTROPY_THRESHOLD: f32 = 0.6;
const ENTROPY_MIN_WORD_LEN: usize = 5;
const ENTROPY_MAX_WORD_LEN: usize = 40;

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
    pub regex_map: BTreeMap<String, EntropyRegex>,
    pub allowlist_map: BTreeMap<String, AllowList>,
    pub pretty_print: bool,
    pub output_path: Option<String>,
    pub entropy_min_word_len: usize,
    pub entropy_max_word_len: usize,
    pub add_entropy_findings: bool,
    pub default_entropy_threshold: f32,
}

#[derive(Debug, Clone)]
pub struct EntropyRegex {
    pub pattern: Regex,
    pub entropy_threshold: Option<f32>,
    pub keyspace: Option<u32>,
    pub make_ascii_lowercase: bool,
}

/// We have to redefine this from regex::bytes because it's struct it has no public constructor
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RustyHogMatch<'t> {
    text: &'t [u8],
    start: usize,
    end: usize,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum PatternEntropy {
    Pattern(String),
    Entropy {
        pattern: String,
        entropy_filter: Option<bool>,
        threshold: Option<String>,
        keyspace: Option<String>,
        make_ascii_lowercase: Option<bool>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum AllowListEnum {
    PatternList(Vec<String>),
    AllowListJson {
        patterns: Vec<String>,
        paths: Option<Vec<String>>,
    },
}

#[derive(Debug, Clone)]
pub struct AllowList {
    pub pattern_list: Vec<Regex>,
    pub path_list: Vec<Regex>,
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
#[derive(Debug, PartialEq, Clone)]
pub struct SecretScannerBuilder {
    pub case_insensitive: bool,
    pub regex_json_str: Option<String>,
    pub regex_json_path: Option<String>,
    pub pretty_print: bool,
    pub output_path: Option<String>,
    pub allowlist_json_path: Option<String>,
    pub default_entropy_threshold: f32,
    pub entropy_min_word_len: usize,
    pub entropy_max_word_len: usize,
    pub add_entropy_findings: bool,
}

impl<'t> RustyHogMatch<'t> {
    /// Returns the starting byte offset of the match in the haystack.
    #[inline]
    pub fn start(&self) -> usize {
        self.start
    }

    /// Returns the ending byte offset of the match in the haystack.
    #[inline]
    pub fn end(&self) -> usize {
        self.end
    }

    /// Returns the range over the starting and ending byte offsets of the
    /// match in the haystack.
    #[inline]
    pub fn range(&self) -> Range<usize> {
        self.start..self.end
    }

    /// Returns the matched text.
    #[inline]
    pub fn as_str(&self) -> &'t [u8] {
        &self.text[self.range()]
    }

    /// Creates a new match from the given haystack and byte offsets.
    #[inline]
    fn new(haystack: &'t [u8], start: usize, end: usize) -> RustyHogMatch<'t> {
        RustyHogMatch {
            text: haystack,
            start,
            end,
        }
    }
}

impl<'t> From<Match<'t>> for RustyHogMatch<'t> {
    fn from(m: Match<'t>) -> RustyHogMatch<'t> {
        RustyHogMatch::new(m.as_bytes(), m.start(), m.end())
    }
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
            allowlist_json_path: None,
            default_entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            entropy_min_word_len: ENTROPY_MIN_WORD_LEN,
            entropy_max_word_len: ENTROPY_MAX_WORD_LEN,
            add_entropy_findings: false,
        }
    }

    /// Configure multiple values using the clap library's `ArgMatches` object.
    /// This function looks for a "CASE" flag and "REGEX", "ALLOWLIST", "DEFAULT_ENTROPY_THRESHOLD" values.
    pub fn conf_argm(mut self, arg_matches: &ArgMatches) -> Self {
        self.case_insensitive = arg_matches.get_flag("CASE");
        self.regex_json_path = match arg_matches.get_one::<String>("REGEX") {
            Some(s) => Some(String::from(s)),
            None => None,
        };
        self.pretty_print = arg_matches.get_flag("PRETTYPRINT");
        self.output_path = match arg_matches.get_one::<String>("OUTPUT") {
            Some(s) => Some(String::from(s)),
            None => None,
        };
        self.allowlist_json_path = match arg_matches.get_one::<String>("ALLOWLIST") {
            Some(s) => Some(String::from(s)),
            None => None,
        };
        self.default_entropy_threshold =
            match arg_matches.get_one::<f32>("DEFAULT_ENTROPY_THRESHOLD") {
                Some(t) => *t,
                None => DEFAULT_ENTROPY_THRESHOLD,
            };
        self.add_entropy_findings = arg_matches.get_flag("ENTROPY");
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

    /// Supply a path to a JSON file on the system that contains allowlists with string
    /// tokens per regular expression
    pub fn set_allowlist_json_path(mut self, allowlist_json_path: &str) -> Self {
        self.allowlist_json_path = Some(String::from(allowlist_json_path));
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

    /// Set default entropy threshold for patterns which enables entropy but do not define a threshold
    pub fn set_default_entropy_threshold(mut self, threshold: f32) -> Self {
        self.default_entropy_threshold = threshold;
        self
    }

    /// Set min word length for entropy calcuation
    pub fn set_entropy_min_word_len(mut self, min_word_len: usize) -> Self {
        self.entropy_min_word_len = min_word_len;
        self
    }

    /// Set max word length for entropy calculation
    pub fn set_entropy_max_word_len(mut self, max_word_len: usize) -> Self {
        self.entropy_max_word_len = max_word_len;
        self
    }

    /// Returns the configured `SecretScanner` object used to perform regex scanning
    pub fn build(&self) -> SecretScanner {
        let json_obj: Result<BTreeMap<String, PatternEntropy>, SimpleError> =
            match &self.regex_json_path {
                Some(p) => Self::build_json_from_file(&Path::new(p)),
                _ => match &self.regex_json_str {
                    Some(s) => Self::build_json_from_str(&s),
                    _ => Self::build_json_from_str(DEFAULT_REGEX_JSON),
                },
            };
        let json_obj: BTreeMap<String, PatternEntropy> = match json_obj {
            Ok(x) => x,
            Err(e) => {
                error!(
                    "Error parsing Regex JSON object, falling back to default regex rules: {:?}",
                    e
                );
                Self::build_json_from_str(DEFAULT_REGEX_JSON).unwrap()
            }
        };
        let regex_map = Self::build_regex_objects(
            json_obj,
            self.case_insensitive,
            self.default_entropy_threshold,
        );
        let output_path = match &self.output_path {
            Some(s) => Some(s.clone()),
            None => None,
        };

        let allowlist_map = match &self.allowlist_json_path {
            Some(p) => {
                let json_string_result = std::fs::read_to_string(p);
                let json_string: String = match json_string_result {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Error reading allowlist JSON file, falling back to default allowlist rules: {:?}", e);
                        String::from(DEFAULT_ALLOWLIST_JSON)
                    }
                };
                Self::build_allowlist_from_str(json_string.as_str())
            }
            _ => Self::build_allowlist_from_str(DEFAULT_ALLOWLIST_JSON),
        };

        let allowlist_map = match allowlist_map {
            Ok(m) => m,
            Err(e) => {
                error!(
                    "Error parsing allowlist JSON object, using an empty allowlist map: {:?}",
                    e
                );
                BTreeMap::new()
            }
        };

        SecretScanner {
            regex_map,
            pretty_print: self.pretty_print,
            output_path,
            allowlist_map,
            entropy_min_word_len: self.entropy_min_word_len,
            entropy_max_word_len: self.entropy_max_word_len,
            add_entropy_findings: self.add_entropy_findings,
            default_entropy_threshold: self.default_entropy_threshold,
        }
    }

    /// Helper function to parse a JSON file path to `Result<BTreeMap<String, Pattern>, SimpleError>`.
    /// This has the side-effect of reading the file-system.
    fn build_json_from_file(
        filename: &Path,
    ) -> Result<BTreeMap<String, PatternEntropy>, SimpleError> {
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

    /// Helper function to parse a JSON string to `Result<BTreeMap<String, Pattern>, SimpleError>`
    pub fn build_json_from_str(
        incoming_str: &str,
    ) -> Result<BTreeMap<String, PatternEntropy>, SimpleError> {
        info!("Attempting to parse JSON regex file from provided string...");
        let content: Map<String, Value> = match serde_json::from_str(incoming_str) {
            Ok(m) => m,
            Err(e) => return Err(SimpleError::with("Failed to parse regex JSON", e)),
        };

        content
            .into_iter()
            .map(|x| {
                let v: PatternEntropy = match serde_json::from_value(x.1) {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(SimpleError::with(
                            "Failed to parse the regex pattern from JSON",
                            e,
                        ))
                    }
                };
                Ok((x.0, v))
            })
            .collect()
    }

    /// Helper function to convert the `BTreeMap<String, Pattern>` generated in `build_json_from...`
    /// to `BTreeMap<String, Regex>` where the key is our "reason" and Regex is a
    /// [regex::bytes::Regex](https://docs.rs/regex/1.3.3/regex/bytes/struct.Regex.html) object.
    fn build_regex_objects(
        json_obj: BTreeMap<String, PatternEntropy>,
        case_insensitive: bool,
        default_entropy_threshold: f32,
    ) -> BTreeMap<String, EntropyRegex> {
        json_obj
            .into_iter()
            .map(|(k, pattern)| match pattern {
                PatternEntropy::Pattern(p) => {
                    let mut regex_builder = RegexBuilder::new(&p);
                    regex_builder.size_limit(10_000_000);
                    if case_insensitive {
                        regex_builder.case_insensitive(true);
                    };
                    (
                        k,
                        EntropyRegex {
                            pattern: regex_builder
                                .build()
                                .unwrap_or_else(|_| panic!("Error parsing regex string: {:?}", p)),
                            entropy_threshold: None,
                            keyspace: None,
                            make_ascii_lowercase: false,
                        },
                    )
                }
                PatternEntropy::Entropy {
                    pattern,
                    entropy_filter,
                    threshold,
                    keyspace,
                    make_ascii_lowercase,
                } => {
                    let mut regex_builder = RegexBuilder::new(&pattern);
                    regex_builder.size_limit(10_000_000);
                    if case_insensitive {
                        regex_builder.case_insensitive(true);
                    };
                    let entropy = match entropy_filter {
                        Some(e) if e => match threshold {
                            Some(t) => Some(t.parse::<f32>().unwrap_or(default_entropy_threshold)),
                            None => Some(default_entropy_threshold),
                        },
                        Some(_) => None,
                        None => None,
                    };
                    let keyspace_processed: Option<u32> = match keyspace {
                        Some(e) => match e.parse::<u32>() {
                            Ok(n) => Some(n),
                            _ => None,
                        },
                        None => None,
                    };
                    let make_ascii_lowercase_processed = make_ascii_lowercase.unwrap_or(false);
                    (
                        k,
                        EntropyRegex {
                            pattern: regex_builder.build().unwrap_or_else(|_| {
                                panic!("Error parsing regex string: {:?}", pattern)
                            }),
                            entropy_threshold: entropy,
                            keyspace: keyspace_processed,
                            make_ascii_lowercase: make_ascii_lowercase_processed,
                        },
                    )
                }
            })
            .collect()
    }

    fn vec_string_to_vec_regex(incoming_array: Vec<String>) -> Vec<Regex> {
        incoming_array
            .into_iter()
            .filter_map(|x| match Regex::new(&x) {
                Ok(r) => Some(r),
                Err(e) => {
                    error!("Failed to parse regex: {}", e);
                    None
                }
            })
            .collect()
    }

    fn build_allowlist_from_str(input: &str) -> Result<BTreeMap<String, AllowList>, SimpleError> {
        info!("Attempting to parse JSON allowlist string");
        let allowlist: BTreeMap<String, AllowListEnum> = match serde_json::from_str(input) {
            Ok(m) => Ok(m),
            Err(e) => Err(SimpleError::with("Failed to parse allowlist JSON", e)),
        }?;
        allowlist
            .into_iter()
            .map(|(p, allowlistobj)| match allowlistobj {
                AllowListEnum::PatternList(v) => {
                    let l = SecretScannerBuilder::vec_string_to_vec_regex(v);
                    Ok((
                        p,
                        AllowList {
                            pattern_list: l,
                            path_list: vec![],
                        },
                    ))
                }
                AllowListEnum::AllowListJson {
                    patterns: pattern_list,
                    paths: path_list,
                } => {
                    let l1 = SecretScannerBuilder::vec_string_to_vec_regex(pattern_list);
                    let l2 = match path_list {
                        Some(v) => SecretScannerBuilder::vec_string_to_vec_regex(v),
                        None => Vec::new(),
                    };
                    Ok((
                        p,
                        AllowList {
                            pattern_list: l1,
                            path_list: l2,
                        },
                    ))
                }
            })
            .collect()
    }
}

impl SecretScanner {
    /// Helper function to set global logging level
    pub fn set_logging(verbose_level: u64) {
        let sl = SimpleLogger::new();
        match verbose_level {
            0 => sl.with_level(LevelFilter::Warn).init().unwrap(),
            1 => sl.with_level(LevelFilter::Info).init().unwrap(),
            2 => sl.with_level(LevelFilter::Debug).init().unwrap(),
            _ => sl.with_level(LevelFilter::Trace).init().unwrap(),
        }
    }

    /// Scan a byte array for regular expression matches, returns a `BTreeMap` of `Matches` for each
    /// regular expression.
    pub fn matches<'a, 'b: 'a>(&'a self, line: &'b [u8]) -> BTreeMap<&'a String, Matches> {
        self.regex_map
            .iter()
            .map(|x| {
                let matches = x.1.pattern.find_iter(line);
                (x.0, matches)
            })
            .collect()
    }

    pub fn matches_entropy<'a, 'b: 'a>(
        &'a self,
        line: &'b [u8],
    ) -> BTreeMap<String, Vec<RustyHogMatch>> {
        //let key: String = String::from("Entropy");
        let mut output: BTreeMap<String, Vec<RustyHogMatch>> = self
            .regex_map
            .iter()
            .map(|x| {
                let matches = x.1.pattern.find_iter(line);
                let matches_filtered: Vec<RustyHogMatch> = matches
                    .filter(|m| self.check_entropy(x.0, &line[m.start()..m.end()]))
                    .filter(|m| !self.is_allowlisted_pattern(x.0, &line[m.start()..m.end()]))
                    .map(RustyHogMatch::from)
                    .inspect(|x| debug!("RustyHogMatch: {:?}", x))
                    .collect();
                (x.0.clone(), matches_filtered)
            })
            .filter(|x| !x.1.is_empty())
            .collect();
        if self.add_entropy_findings {
            let entropy_findings =
                SecretScanner::entropy_findings(line, self.default_entropy_threshold);
            if !entropy_findings.is_empty() {
                output.insert(String::from("Entropy"), entropy_findings);
                debug!("matches_entropy findings: {:?}", output);
            }
        }
        // debug!("matches_entropy findings: {:?}", output);
        output
    }

    /// Helper function to determine whether a byte array only contains valid Base64 characters.
    fn is_base64_string(string_in: &[u8]) -> bool {
        let hashset_string_in: HashSet<&u8> = string_in.iter().collect();
        hashset_string_in.is_subset(&B64_ENCODE.iter().collect())
    }

    /// Helper function to determine whether a byte array only contains valid hex characters.
    fn is_hex_string(string_in: &[u8]) -> bool {
        let hashset_string_in: HashSet<&u8> = string_in.iter().collect();
        hashset_string_in.is_subset(&HEX_ENCODE.iter().collect())
    }

    /// Compute the Shannon entropy for a byte array (from https://docs.rs/crate/entropy/0.3.0/source/src/lib.rs)
    fn calc_shannon_entropy(bytes: &[u8], make_ascii_lowercase: bool) -> f32 {
        let mut entropy = 0.0;
        let mut counts: HashMap<u8, i32> = HashMap::new();

        // there may be better ways to make this code shorter, but this method prevents byte copies
        // if make_ascii_lowercase is set to false
        if make_ascii_lowercase {
            for &b in bytes {
                let mut c = b;
                c.make_ascii_lowercase();
                counts.insert(c, counts.get(&c).unwrap_or(&0) + 1);
            }
        } else {
            for &b in bytes {
                counts.insert(b, counts.get(&b).unwrap_or(&0) + 1);
            }
        }

        for &count in counts.values() {
            let p: f32 = (count as f32) / (bytes.len() as f32);
            entropy -= p * p.log(2.0);
        }

        entropy
    }

    fn guess_keyspace(bytes: &[u8]) -> (u32, bool) {
        if SecretScanner::is_base64_string(bytes) {
            return (64, false);
        };
        if SecretScanner::is_hex_string(bytes) {
            return (16, true);
        };
        (128, false)
    }

    /// Because the Shannon entropy number alone does not have context of the keyspace, we use this
    /// function to determine the amount of entropy present in a string as a value between 0-1.
    /// See https://stats.stackexchange.com/questions/281093/shannon-entropy-metric-entropy-and-relative-entropy
    fn calc_normalized_entropy(
        bytes: &[u8],
        keyspace: Option<u32>,
        make_ascii_lowercase: bool,
    ) -> f32 {
        let (processed_keyspace, processed_lowercase): (u32, bool) = match keyspace {
            Some(n) => (n, make_ascii_lowercase),
            None => SecretScanner::guess_keyspace(bytes),
        };
        let raw_entropy = SecretScanner::calc_shannon_entropy(bytes, processed_lowercase);
        raw_entropy / ((processed_keyspace as f32).log2())
    }

    /// Scan a byte array for arbitrary hex sequences and base64 sequences. Will return a list of
    /// matches for those sequences with a high amount of entropy, potentially indicating a
    /// private key.
    pub fn entropy_findings(line: &[u8], entropy_threshold: f32) -> Vec<RustyHogMatch> {
        // The efficency of this could likely be improved
        let words: Vec<&[u8]> = line.split(|x| WORD_SPLIT.contains(x)).collect();
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
        let b64_words: Vec<String> = words
            .iter()
            .filter(|word| word.len() >= 20 && Self::is_base64_string(word))
            .filter_map(|x| Base64Engine::STANDARD_NO_PAD.decode(x).ok())
            .filter(|word| {
                Self::calc_normalized_entropy(word, Some(255), false) > entropy_threshold
            })
            .map(|word| String::from(Base64Engine::STANDARD_NO_PAD.encode(&word).as_str()))
            .collect();
        let hex_words: Vec<String> = words
            .iter() // there must be a better way
            .filter(|word| (word.len() >= 20) && (word.iter().all(u8::is_ascii_hexdigit)))
            .filter_map(|&x| hex::decode(x).ok())
            .filter(|word| Self::calc_normalized_entropy(word, Some(255), true) > entropy_threshold)
            .map(hex::encode)
            .collect();
        //dedup first to prevent some strings from getting detected twice
        if !b64_words.is_empty() || !hex_words.is_empty() {
            debug!("b64_words: {:?}", b64_words);
            debug!("hex_words: {:?}", hex_words);
        }
        let mut output_hashset: HashSet<String> = HashSet::new();
        for word in b64_words {
            output_hashset.insert(word);
        }
        for word in hex_words {
            output_hashset.insert(word);
        }
        let mut output = Vec::new();
        for word in output_hashset {
            // There should be a better way to do this. This seems expensive
            let vec_line = String::from_utf8(Vec::from(line)).unwrap_or_else(|_| String::from(""));
            let index = vec_line.find(&word).unwrap_or(0);
            if index > line.len() {
                error!("index error");
            } else {
                let m: RustyHogMatch = RustyHogMatch {
                    text: line,
                    start: index,
                    end: index + word.len(),
                };
                output.push(m);
            }
        }
        if !output.is_empty() {
            debug!("entropy_findings output: {:?}", output);
        }
        output
    }

    /// Truncate a slice to the max_len, or returns the original slice when is shorter than that
    fn truncate_slice(word: &[u8], max_len: usize) -> &[u8] {
        if word.len() > max_len {
            return &word[..max_len];
        }
        word
    }

    /// Find the word with the maximum entropy in a byte array. It will filter out all words with the length
    /// smaller than min_word_len. In addition, it will truncate the lengthy words to max_word_len. Will return
    /// the maximum entropy.
    fn find_max_entropy(
        &self,
        line: &[u8],
        keyspace: Option<u32>,
        make_ascii_lowercase: bool,
    ) -> f32 {
        let words: Vec<&[u8]> = line.split(|x| WORD_SPLIT.contains(x)).collect();
        // println!("words: {:?}", words);
        let words_entropy: Vec<(&[u8], f32)> = words
            .iter()
            .filter(|word| (word.len() >= self.entropy_min_word_len))
            .map(|word| {
                (
                    *word,
                    Self::calc_normalized_entropy(
                        Self::truncate_slice(&word, self.entropy_max_word_len),
                        keyspace,
                        make_ascii_lowercase,
                    ),
                )
            })
            .collect();
        let mut max_entropy: f32 = 0.0;
        // println!("{:?}", words_entropy);
        for &(_, entropy) in &words_entropy {
            if entropy > max_entropy {
                max_entropy = entropy;
            }
        }
        max_entropy
    }

    /// Checks the entropy of a text for a given pattern defined into the regex_map. If the entropy is greater than the
    /// predefined entropy threshold return true, otherwise false. Always returns true for patterns without entropy threshold
    /// and skip the entropy calculation.
    pub fn check_entropy(&self, pattern: &str, text: &[u8]) -> bool {
        if let Some(entry) = self.regex_map.get(pattern) {
            match entry.entropy_threshold {
                Some(entropy_threshold) => {
                    let entropy_threshold_corrected =
                        if entropy_threshold > 1.0 && entropy_threshold <= 8.0 {
                            info!("entropy_threshold values should now be between 0 and 1");
                            entropy_threshold / 8.0
                        } else if entropy_threshold > 8.0 {
                            error!(
                                "invalid entropy_threshold value {} provided, defaulting to {}",
                                entropy_threshold, DEFAULT_ENTROPY_THRESHOLD
                            );
                            DEFAULT_ENTROPY_THRESHOLD
                        } else {
                            entropy_threshold
                        };
                    // println!("find_max_entropy({:?})", text);
                    let max_entropy =
                        self.find_max_entropy(text, entry.keyspace, entry.make_ascii_lowercase);
                    max_entropy > entropy_threshold_corrected
                }
                None => true,
            }
        } else {
            pattern == "Entropy"
        }
    }

    /// Helper function that takes a HashSet of serializable structs and outputs them as JSON
    /// Side effect: May write to the file-system based on `self.output_path`
    pub fn output_findings<T: Serialize + Eq + Hash>(
        &self,
        findings: &HashSet<T>,
    ) -> anyhow::Result<()> {
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

    /// Checks if the provided path name is allowlisted
    pub fn is_allowlisted_path(&self, pattern: &str, path: &[u8]) -> bool {
        if let Some(allowlist) = self.allowlist_map.get(pattern) {
            if allowlist.path_list.iter().any(|x| x.find(path).is_some()) {
                return true;
            }
        }
        if let Some(allowlist) = self.allowlist_map.get("<GLOBAL>") {
            if allowlist.path_list.iter().any(|x| x.find(path).is_some()) {
                return true;
            }
        }
        false
    }

    /// Checks if the provided token is allowlisted
    pub fn is_allowlisted_pattern(&self, pattern: &str, token: &[u8]) -> bool {
        if let Some(allowlist) = self.allowlist_map.get(pattern) {
            if allowlist
                .pattern_list
                .iter()
                .any(|x| x.find(token).is_some())
            {
                return true;
            }
        }
        if let Some(allowlist) = self.allowlist_map.get("<GLOBAL>") {
            if allowlist
                .pattern_list
                .iter()
                .any(|x| x.find(token).is_some())
            {
                return true;
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
                Some(r) => r.pattern.as_str() == v.pattern.as_str(),
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
        for (k, v) in &self.regex_map {
            k.hash(state);
            v.pattern.as_str().hash(state);
        }
        if self.pretty_print {
            "prettyprintyes".hash(state)
        } else {
            "prettyprintno".hash(state)
        }
        match self.output_path.as_ref() {
            None => "outputpathno".hash(state),
            Some(s) => s.hash(state),
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
    use encoding::all::ASCII;
    use encoding::{DecoderTrap, Encoding};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_entropy_findings() {
        let test_string = String::from(
            r#"
            secret: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg
            another_secret = "1dd06c1162b44890b97ad27849f1c1ef"
            secret:aea7f86653514d94b86cc33a5bad1659
            hex_bytes: 9a303808fabab57e8dfc88ed6b3a287ba47c8da7da7e7d622a8333d4c28f
            not_so_secret_but_has_the_word_secret_and_is_long
        "#,
        )
            .into_bytes();
        let output = SecretScanner::entropy_findings(test_string.as_slice(), 0.6);
        // println!("{:?}", output);
        assert_eq!(output.len(), 1);
    }

    #[test]
    fn test_truncate_slice() {
        let output = SecretScanner::truncate_slice(
            "secret: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg".as_bytes(),
            10,
        );
        assert_eq!(output, "secret: AB".as_bytes())
    }

    #[test]
    fn test_find_max_entropy() {
        let ssb = SecretScannerBuilder::new();
        let ss = ssb.build();
        let output = ss.find_max_entropy(
            "secret: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg".as_bytes(),
            Some(128),
            false,
        );
        assert_eq!(output, 0.72062784);
    }

    #[test]
    fn test_check_entropy() {
        let ssb = SecretScannerBuilder::new();
        let ss = ssb.build();
        let output = ss.check_entropy(
            "Generic Secret",
            "secret: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg".as_bytes(),
        );
        assert!(output);
        let output2 = ss.check_entropy(
            "Generic Secret",
            "secret: AAAAAAAAABBBBBBBBBBBBCCCCCCCCCCCC".as_bytes(),
        );
        assert!(!output2);
    }

    #[test]
    fn generic_secret_regex_test() {
        let ssb = SecretScannerBuilder::new();
        let ss = ssb.build();
        let test_string = String::from(
            r#"
            secret: gfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA
            another_secret = "1dd06c1162b44890b97ad27849f1c1ef"
            secret:aea7f86653514d94b86cc33a5bad1659
            not_so_secret_but_has_the_word_secret_and_is_long
        "#,
        )
            .into_bytes();
        let mut findings: Vec<(String, String)> = Vec::new();
        // Main loop - split the data based on newlines, then run get_matches() on each line,
        // then make a list of findings in output
        let lines = test_string.split(|&x| (x as char) == '\n');
        for (_index, new_line) in lines.enumerate() {
            let results = ss.matches_entropy(new_line);
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
                    findings.push((r, new_line_string));
                }
            }
        }
        // if findings.len() != 1 {
        for f in &findings {
            println!("{} {}", f.0, f.1);
        }
        // }
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn email_address_regex_test() {
        let ssb = SecretScannerBuilder::new();
        let ss = ssb.build();
        let test_string = String::from(
            r#"
            anactualemail@gmail.com
            git@github.com:newrelic/rusty-hog-scanner.git
            scp user@host:file.txt .
            https://user@host/secured/file
            https://user@host.com/secured/file
            <text>@<text>
        "#,
        )
            .into_bytes();
        let mut findings: Vec<(String, String)> = Vec::new();
        // Main loop - split the data based on newlines, then run get_matches() on each line,
        // then make a list of findings in output
        let lines = test_string.split(|&x| (x as char) == '\n');
        for (_index, new_line) in lines.enumerate() {
            let results = ss.matches_entropy(new_line);
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
                    findings.push((r, new_line_string));
                }
            }
        }
        // if findings.len() != 1 {
        for f in &findings {
            println!("{} {}", f.0, f.1);
        }
        // }
        assert_eq!(findings.len(), 1);
        let f = findings.pop().unwrap();
        assert_eq!(f.0, "Email address");
        assert_eq!(f.1, "            anactualemail@gmail.com");
    }

    #[test]
    fn can_parse_json_from_str() -> Result<(), String> {
        let builder = SecretScannerBuilder::build_json_from_str(
            r#"
        {
            "Pattern name 1": "test",
            "Pattern name 2": {
                "pattern": "test"
            },
            "Pattern name 3": {
                "pattern": "test",
                "entropy_filter": true
            },
            "Pattern name 4": {
                "pattern": "test",
                "entropy_filter": true,
                "threshold": "4.5"
            }
        }
        "#,
        );
        if let Err(m) = builder {
            return Err(format! {"failed pasing valid json from str: {}", m});
        }
        Ok(())
    }

    #[test]
    fn can_parse_json_from_file() -> Result<(), String> {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"
        {
            "Pattern name 1": "test",
            "Pattern name 2": {
                "pattern": "test"
            },
            "Pattern name 3": {
                "pattern": "test",
                "entropy_filter": true
            },
            "Pattern name 4": {
                "pattern": "test",
                "entropy_filter": true,
                "threshold": "4.5"
            }
        }
        "#;
        file.write(json.as_bytes()).unwrap();

        if let Err(m) = SecretScannerBuilder::build_json_from_file(file.path()) {
            return Err(format!("failed parsing valid json from file: {}", m));
        }
        Ok(())
    }

    #[test]
    fn can_build_secret_scanner_with_various_entropy_options() {
        let json = r#"
        {
            "Pattern1": "test",
            "Pattern2": {
                "pattern": "test"
            },
            "Pattern3": {
                "pattern": "test",
                "entropy_filter": false
            },
            "Pattern4": {
                "pattern": "test",
                "entropy_filter": true
            },
            "Pattern5": {
                "pattern": "test",
                "entropy_filter": true,
                "threshold": "4.5"
            }
        }
        "#;

        let builder = SecretScannerBuilder::new();
        let scanner = builder
            .set_json_str(&json)
            .set_default_entropy_threshold(2.0)
            .build();
        let p1 = scanner.regex_map.get("Pattern1").unwrap();
        assert_eq!(p1.entropy_threshold, None);
        let p2 = scanner.regex_map.get("Pattern2").unwrap();
        assert_eq!(p2.entropy_threshold, None);
        let p3 = scanner.regex_map.get("Pattern3").unwrap();
        assert_eq!(p3.entropy_threshold, None);
        let p4 = scanner.regex_map.get("Pattern4").unwrap();
        assert_eq!(p4.entropy_threshold, Some(2.0));
        let p5 = scanner.regex_map.get("Pattern5").unwrap();
        assert_eq!(p5.entropy_threshold, Some(4.5));
    }

    #[test]
    fn can_parse_allowlist_from_str() -> Result<(), String> {
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

        if let Err(e) = SecretScannerBuilder::build_allowlist_from_str(json) {
            return Err(format!("failed parsing valid allowlist JSON file: {}", e));
        }

        Ok(())
    }
}

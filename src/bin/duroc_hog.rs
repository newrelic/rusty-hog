//! File system secret scanner in Rust
//!
//! # Usage
//! ```
//!     duroc_hog [FLAGS] [OPTIONS] <FSPATH>
//!
//!FLAGS:
//!        --caseinsensitive    Sets the case insensitive flag for all regexes
//!        --entropy            Enables entropy scanning
//!        --prettyprint        Outputs the JSON in human readable format
//!        --recursive          Scans all subdirectories underneath the supplied path
//!        --archives           Scans archives within the directory
//!    -v, --verbose            Sets the level of debugging information
//!    -h, --help               Prints help information
//!    -V, --version            Prints version information
//!
//!OPTIONS:
//!    -o, --outputfile <OUTPUT>            Sets the path to write the scanner results to (stdout by default)
//!    -r, --regex <REGEX>                  Sets a custom regex JSON file, defaults to built-in

//!
//!ARGS:
//!    <FSPATH>    Sets the path of the file system to scan.
//! ```

#[macro_use]
extern crate clap;

extern crate tempdir;

extern crate chrono;

extern crate encoding;

use clap::ArgMatches;
use log::{self, debug, info, error};
use serde::{Deserialize, Serialize};
use simple_error::SimpleError;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::{io, str};
use walkdir::{WalkDir};

use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use rusty_hogs::{SecretScanner, SecretScannerBuilder};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
/// `serde_json` object that represents a single found secret - finding
pub struct FileFinding {
    //    branch: String, // this requires a walk of the commits for each finding, so lets leave it out for the moment
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub path: String,
    pub reason: String,
    pub linenum: usize,
    pub diff: String,
}

const ZIPEXTENSIONS: &[&str] = &["zip"];
const TAREXTENSIONS: &[&str] = &["tar", "gem"];
const GZEXTENSIONS: &[&str] = &["gz", "tgz"];

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
fn main() {
    let matches = clap_app!(duroc_hog =>
        (version: "1.0.4")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "File system secret scanner in Rust")
        (@arg REGEX: -r --regex +takes_value "Sets a custom regex JSON file")
        (@arg FSPATH: +required "Sets the path of the directory or file to scan.")
        (@arg RECURSIVE: --recursive "Scans all subdirectories underneath the supplied path")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        // (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg UNZIP: -z --unzip "Recursively scans archives (ZIP and TAR) in memory (dangerous)")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Outputs the JSON in human readable format")
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
    // let scan_entropy = arg_matches.is_present("ENTROPY");
    let recursive = arg_matches.is_present("RECURSIVE");
    let fspath = Path::new(arg_matches.value_of("FSPATH").unwrap());
    let unzip: bool = arg_matches.is_present("UNZIP");

    debug!("fspath: {:?}", fspath);

    // First verify the path
    if !Path::exists(fspath) {
        return Err(SimpleError::new("Path does not exist"));
    } else {
        info!("path verification succeeded");
    }

    let mut output: HashSet<FileFinding> = HashSet::new();

    if Path::is_dir(fspath) {
        output.extend(scan_dir(fspath, &secret_scanner, recursive, unzip));
    } else {
        let f = File::open(fspath).unwrap();
        output.extend(scan_file(fspath, &secret_scanner, f, "", unzip));
    }

    info!("Found {} secrets", output.len());
    match secret_scanner.output_findings(&output) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with("failed to output findings", SimpleError::new(err.to_string())))
    }
}

fn scan_dir(
    fspath: &Path,
    ss: &SecretScanner,
    recursive: bool,
    unzip: bool,
) -> HashSet<FileFinding> {
    let mut output: HashSet<FileFinding> = HashSet::new();
    if recursive {
        for entry in WalkDir::new(fspath).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let f = File::open(entry.path()).unwrap();
                let mut inner_findings = scan_file(entry.path(), &ss, f, "", unzip);
                for d in inner_findings.drain() {
                    output.insert(d);
                }
            }
        }
    } else {
        let dir_contents: Vec<PathBuf> = fspath
            .read_dir()
            .expect("read_dir call failed")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().unwrap().is_file())
            .map(|e| e.path())
            .collect();
        debug!("dir_contents: {:?}", dir_contents);
        for file_path in dir_contents {
            let path = file_path.clone();
            let f = File::open(file_path).unwrap();
            let mut inner_findings = scan_file(&path, &ss, f, "", unzip);
            for d in inner_findings.drain() {
                info!("FileFinding: {:?}", d);
                output.insert(d);
            }
            debug!("inner findings: {:?}", inner_findings);
        }
    }
    output
}

fn scan_file<R: Read + io::Seek>(
    file_path: &Path,
    ss: &SecretScanner,
    mut reader: R,
    path_prefix: &str,
    unzip: bool,
) -> HashSet<FileFinding> {
    let mut findings: HashSet<FileFinding> = HashSet::new();
    let path_string = String::from(Path::new(path_prefix).join(file_path).to_str().unwrap());
    info!("scan_file({:?})", path_string);
    let ext: String = match file_path.extension() {
        Some(osstr) => String::from(osstr.to_str().unwrap_or_else(|| "")).to_ascii_lowercase(),
        None => String::from(""),
    };

    // https://stackoverflow.com/questions/23975391/how-to-convert-a-string-into-a-static-str
    if ZIPEXTENSIONS.contains(&&*ext) && unzip {
        let mut zip = zip::ZipArchive::new(reader).unwrap();
        for i in 0..zip.len() {
            let mut innerfile = zip.by_index(i).unwrap();
            // by using read_to_end we are decompressing the data (expensive)
            // and moving it (inefficient) *but* that means we can recursively decompress
            let mut innerdata: Vec<u8> = Vec::new();
            let read_result = innerfile.read_to_end(&mut innerdata);
            if read_result.is_err() { info!("read error within ZIP file"); continue; }
            let new_reader = Cursor::new(innerdata);
            let mut inner_findings = scan_file(
                innerfile.sanitized_name().as_path(),
                ss,
                new_reader,
                &path_string,
                unzip,
            );
            for d in inner_findings.drain() {
                info!("FileFinding: {:?}", d);
                findings.insert(d);
            }
        }
        findings
    } else if TAREXTENSIONS.contains(&&*ext) && unzip {
        let mut tarobj = tar::Archive::new(reader);
        let tar_entries = tarobj.entries().unwrap();
        for entry_result in tar_entries {
            let mut inner_entry = entry_result.unwrap();
            let mut innerdata: Vec<u8> = Vec::new();
            let read_result = inner_entry.read_to_end(&mut innerdata);
            if read_result.is_err() { info!("read error within TAR file"); continue; }
            let new_reader = Cursor::new(innerdata);
            let mut inner_findings = scan_file(
                inner_entry.path().unwrap().as_ref(),
                ss,
                new_reader,
                &path_string,
                unzip,
            );
            for d in inner_findings.drain() {
                info!("FileFinding: {:?}", d);
                findings.insert(d);
            }
        }
        findings
    } else if GZEXTENSIONS.contains(&&*ext) && unzip {
        let mut decompressor = flate2::read::GzDecoder::new(reader);
        let mut innerdata: Vec<u8> = Vec::new();
        let read_result = decompressor.read_to_end(&mut innerdata);
        if read_result.is_err() { info!("read error within ZIP file"); return findings; }
        let new_reader = Cursor::new(innerdata);
        let mut tempstring = String::from(file_path.file_stem().unwrap().to_str().unwrap());
        if ext.to_ascii_lowercase() == "tgz" {
            tempstring.push_str(".tar");
        }
        let inner_path: &Path = Path::new(&tempstring);
        info!("gunzip inner path: {:?}", inner_path);
        let mut inner_findings = scan_file(
            inner_path,
            ss,
            new_reader,
            &path_string,
            unzip,
        );
        for d in inner_findings.drain() {
            info!("FileFinding: {:?}", d);
            findings.insert(d);
        }
        findings
    } else {
        let mut data = Vec::new();
        let read_result = reader.read_to_end(&mut data);
        if read_result.is_err() { info!("read error for file {}", path_string); }
        scan_bytes(data, ss, path_string)
    }
}

fn scan_bytes(input: Vec<u8>, ss: &SecretScanner, path: String) -> HashSet<FileFinding> {
    info!("scan_bytes: {:?}", path);
    let mut findings: HashSet<FileFinding> = HashSet::new();
    // Main loop - split the data based on newlines, then run get_matches() on each line,
    // then make a list of findings in output
    let lines = input.split(|&x| (x as char) == '\n');
    for (index, new_line) in lines.enumerate() {
        let results = ss.matches(new_line);
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
                findings.insert(FileFinding {
                    diff: new_line_string,
                    strings_found,
                    reason: r.clone(),
                    path: path.clone(),
                    linenum: index + 1,
                });
            }
        }
    }
    findings
}

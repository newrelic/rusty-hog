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
use log::{self, info, debug};
use simple_error::SimpleError;
use std::str;
use std::path::{Path, PathBuf};
use tempdir::TempDir;
use walkdir::{WalkDir, DirEntry};

use rusty_hogs::git_scanning::GitScanner;
use rusty_hogs::{SecretScanner, SecretScannerBuilder};

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
fn main() {
    let matches = clap_app!(choctaw_hog =>
        (version: "1.0.3")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "File system secret scanner in Rust")
        (@arg REGEX: -r --regex +takes_value "Sets a custom regex JSON file")
        (@arg FSPATH: +required "Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)")
        (@arg RECURSIVE: --recursive "Scans all subdirectories underneath the supplied path")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Outputs the JSON in human readable format")
    )
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => panic!("error: {}", e),
    }
}

/// Main logic contained here. Get the CLI variables, and use them to initialize a GitScanner
fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    // Set logging
    SecretScanner::set_logging(arg_matches.occurrences_of("VERBOSE"));

    // Initialize some more variables
    let secret_scanner = SecretScannerBuilder::new().conf_argm(arg_matches).build();
    let scan_entropy = arg_matches.is_present("ENTROPY");
    let recursive = arg_matches.is_present("RECURSIVE");
    let fspath = Path::new(arg_matches.value_of("FSPATH").unwrap());
    debug!("fspath: {:?}", fspath);

    // First verify the path
    if !Path::exists(fspath) {
        return Err(SimpleError::new("Path does not exist"));
    } else {
        info!("path verification succeeded");
    }

    if Path::is_dir(fspath) {
        if recursive {
            for entry in WalkDir::new(fspath).into_iter().filter_map(|e| e.ok()) {
                scan_file(entry.path());
            }
        } else {
            let dir_contents: Vec<PathBuf> = fspath.read_dir()
                .expect("read_dir call failed")
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().unwrap().is_file())
                .map(|e| e.path())
                .collect();
            info!("dir_contents: {:?}", dir_contents);
            for file_path in dir_contents {
                scan_file(file_path.as_path());
            }
        }

    }

    fn scan_file(file_path: &Path) {
        info!("scan_file({:?})", file_path);
    }

    Ok(())
}
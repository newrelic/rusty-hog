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
//!        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
//!    -a, --allowlist <ALLOWLIST>          Sets a custom allowlist JSON file
//!    -o, --outputfile <OUTPUT>            Sets the path to write the scanner results to (stdout by default)
//!    -r, --regex <REGEX>                  Sets a custom regex JSON file, defaults to built-in

//!
//!ARGS:
//!    <FSPATH>    Sets the path of the file system to scan.
//! ```

extern crate clap;

extern crate tempdir;

extern crate chrono;

extern crate encoding;

use clap::{Arg, ArgAction, ArgMatches, Command};
use log::{self, debug, error, info};
use serde::{Deserialize, Serialize};
use simple_error::SimpleError;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::{io, str};
use walkdir::WalkDir;

use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use path_clean::PathClean;
use rusty_hog_scanner::{SecretScanner, SecretScannerBuilder};
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
    let matches = Command::new("duroc_hog")
        .version("1.0.11")
        .author("Scott Cutler <scutler@newrelic.com>")
        .about("File system secret scanner in Rust")
        .arg(
            Arg::new("REGEX")
                .short('r')
                .long("regex")
                .action(ArgAction::Set)
                .value_name("REGEX")
                .help("Sets a custom regex JSON file"),
        )
        .arg(
            Arg::new("FSPATH")
                .required(true)
                .action(ArgAction::Set)
                .value_name("PATH")
                .help("Sets the path of the directory or file to scan."),
        )
        .arg(
            Arg::new("NORECURSIVE")
                .long("norecursive")
                .action(ArgAction::SetTrue)
                .help(
                    "Disable recursive scanning of all subdirectories underneath the supplied path",
                ),
        )
        .arg(
            Arg::new("VERBOSE")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .help("Sets the level of debugging information"),
        )
        .arg(
            Arg::new("ENTROPY")
                .long("entropy")
                .action(ArgAction::SetTrue)
                .help("Enables entropy scanning"),
        )
        .arg(
            Arg::new("DEFAULT_ENTROPY_THRESHOLD")
                .long("default_entropy_threshold")
                .action(ArgAction::Set)
                .default_value("0.6")
                .help("Default entropy threshold (0.6 by default)"),
        )
        .arg(
            Arg::new("UNZIP")
                .short('z')
                .long("unzip")
                .action(ArgAction::SetTrue)
                .help("Recursively scans archives (ZIP and TAR) in memory (dangerous)"),
        )
        .arg(
            Arg::new("CASE")
                .long("caseinsensitive")
                .action(ArgAction::SetTrue)
                .help("Sets the case insensitive flag for all regexes"),
        )
        .arg(
            Arg::new("OUTPUT")
                .short('o')
                .long("outputfile")
                .action(ArgAction::Set)
                .help("Sets the path to write the scanner results to (stdout by default)"),
        )
        .arg(
            Arg::new("PRETTYPRINT")
                .long("prettyprint")
                .action(ArgAction::SetTrue)
                .help("Outputs the JSON in human readable format"),
        )
        .arg(
            Arg::new("ALLOWLIST")
                .short('a')
                .long("allowlist")
                .action(ArgAction::Set)
                .help("Sets a custom allowlist JSON file"),
        )
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => error!("Error running command: {}", e),
    }
}

/// Main logic contained here. Get the CLI variables, and use them to initialize a GitScanner
fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    // Set logging
    SecretScanner::set_logging(arg_matches.get_count("VERBOSE").into());

    // Initialize some more variables
    let secret_scanner = SecretScannerBuilder::new().conf_argm(arg_matches).build();
    // let scan_entropy = arg_matches.is_present("ENTROPY");
    let recursive = !arg_matches.get_flag("NORECURSIVE");
    let fspath = Path::new(arg_matches.get_one::<String>("FSPATH").unwrap());
    let default_path = String::from("");
    let output_file = Path::new(arg_matches.get_one("OUTPUT").unwrap_or(&default_path));
    let unzip: bool = arg_matches.get_flag("UNZIP");

    debug!("fspath: {:?}", fspath);

    // First verify the path
    if !Path::exists(fspath) {
        return Err(SimpleError::new("Path does not exist"));
    } else {
        info!("path verification succeeded");
    }

    let mut output: HashSet<FileFinding> = HashSet::new();

    if Path::is_dir(fspath) {
        output.extend(scan_dir(
            fspath,
            output_file,
            &secret_scanner,
            recursive,
            unzip,
        ));
    } else {
        let f = File::open(fspath).unwrap();
        output.extend(scan_file(fspath, &secret_scanner, f, "", unzip));
    }

    let output: HashSet<FileFinding> = output
        .into_iter()
        .filter(|ff| !secret_scanner.is_allowlisted_path(&ff.reason, ff.path.as_bytes()))
        .collect();

    info!("Found {} secrets", output.len());
    match secret_scanner.output_findings(&output) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with(
            "failed to output findings",
            SimpleError::new(err.to_string()),
        )),
    }
}

fn scan_dir(
    fspath: &Path,
    output_file: &Path,
    ss: &SecretScanner,
    recursive: bool,
    unzip: bool,
) -> HashSet<FileFinding> {
    let mut output: HashSet<FileFinding> = HashSet::new();

    let scanning_closure = |file_path: &Path| {
        let f = File::open(file_path).unwrap();
        let mut inner_findings = scan_file(file_path, &ss, f, "", unzip);
        for d in inner_findings.drain() {
            output.insert(d);
        }
    };

    if recursive {
        recursive_dir_scan(fspath, Path::new(output_file), scanning_closure)
    } else {
        flat_dir_scan(fspath, Path::new(output_file), scanning_closure)
    };

    output
}

fn recursive_dir_scan<C>(fspath: &Path, output_file: &Path, mut closure: C)
where
    C: FnMut(&Path),
{
    for entry in WalkDir::new(fspath).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && PathBuf::from(entry.path()).clean() != output_file {
            closure(&entry.path());
        }
    }
}

fn flat_dir_scan<C>(fspath: &Path, output_file: &Path, mut closure: C)
where
    C: FnMut(&Path),
{
    let dir_contents: Vec<PathBuf> = fspath
        .read_dir()
        .expect("read_dir call failed")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| e.path())
        .inspect(|e| {
            debug!(
                "clean path: {:?}, output_file: {:?}",
                &e.clean(),
                output_file
            )
        })
        .filter(|e| e.clean() != output_file)
        .collect();
    debug!("dir_contents: {:?}", dir_contents);

    for file_path in dir_contents {
        closure(&file_path);
    }
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
        Some(osstr) => String::from(osstr.to_str().unwrap_or("")).to_ascii_lowercase(),
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
            if read_result.is_err() {
                info!("read error within ZIP file");
                continue;
            }
            let new_reader = Cursor::new(innerdata);
            let mut inner_findings = scan_file(
                innerfile.enclosed_name().unwrap(),
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
            if read_result.is_err() {
                info!("read error within TAR file");
                continue;
            }
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
        if read_result.is_err() {
            info!("read error within ZIP file");
            return findings;
        }
        let new_reader = Cursor::new(innerdata);
        let mut tempstring = String::from(file_path.file_stem().unwrap().to_str().unwrap());
        if ext.to_ascii_lowercase() == "tgz" {
            tempstring.push_str(".tar");
        }
        let inner_path: &Path = Path::new(&tempstring);
        info!("gunzip inner path: {:?}", inner_path);
        let mut inner_findings = scan_file(inner_path, ss, new_reader, &path_string, unzip);
        for d in inner_findings.drain() {
            info!("FileFinding: {:?}", d);
            findings.insert(d);
        }
        findings
    } else {
        let mut data = Vec::new();
        let read_result = reader.read_to_end(&mut data);
        if read_result.is_err() {
            info!("read error for file {}", path_string);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use escargot::CargoBuild;
    use std::io::Result;
    use std::io::Write;
    use std::process::Output;
    use tempfile::{NamedTempFile, TempDir};

    fn run_command_in_dir(dir: &TempDir, command: &str, args: &[&str]) -> Result<Output> {
        let dir_path = dir.path().to_str().unwrap();
        let binary = CargoBuild::new().bin(command).run().unwrap();

        binary.command().current_dir(dir_path).args(args).output()
    }

    fn write_temp_file(dir: &TempDir, filename: &str, contents: &str) {
        let file_path = dir.path().join(filename);
        let mut tmp_file = File::create(&file_path).unwrap();
        write!(tmp_file, "{}", contents).unwrap();
    }

    fn read_temp_file(dir: &TempDir, filename: &str) -> String {
        let mut contents = String::new();
        let file_path = dir.path().join(filename);
        let mut file_handle = File::open(&file_path).unwrap();
        file_handle.read_to_string(&mut contents).unwrap();
        contents
    }

    #[test]
    fn does_not_scan_output_file() {
        let temp_dir = TempDir::new().unwrap();

        write_temp_file(
            &temp_dir,
            "insecure-file.txt",
            "My email is username@mail.com",
        );

        let cmd_args = ["-o", "output_file.txt", "."];

        run_command_in_dir(&temp_dir, "duroc_hog", &cmd_args).unwrap();

        run_command_in_dir(&temp_dir, "duroc_hog", &cmd_args).unwrap();

        let text = read_temp_file(&temp_dir, "output_file.txt");

        println!("{}", text);

        assert!(text.contains("\"path\":\"./insecure-file.txt\""));
        assert!(!text.contains("output_file.txt"));
    }

    #[test]
    fn allowlist_json_file_prevents_output() {
        let temp_dir = TempDir::new().unwrap();
        let mut allowlist_temp_file = NamedTempFile::new().unwrap();
        let json = r#"
        {
            "Email address": [
                "username@mail.com"
            ]
        }
        "#;
        write!(allowlist_temp_file, "{}", json).unwrap();
        write_temp_file(
            &temp_dir,
            "insecure-file.txt",
            "My email is username@mail.com",
        );

        let cmd_args = [
            "--allowlist",
            allowlist_temp_file.path().to_str().unwrap(),
            ".",
        ];

        let output = run_command_in_dir(&temp_dir, "duroc_hog", &cmd_args).unwrap();

        assert_eq!("[]\n", str::from_utf8(&output.stdout).unwrap());
    }
}

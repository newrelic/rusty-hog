#[macro_use]
extern crate clap;

extern crate tempdir;

extern crate chrono;

extern crate encoding;

use chrono::NaiveDateTime;

use clap::ArgMatches;
use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use git2::DiffFormat;
use git2::{DiffOptions, Repository, Time};
use log::{self, info};
use regex::bytes::Matches;
use secret_scanning::SecretScanner;
use serde::{Deserialize, Serialize};
use simple_error::SimpleError;
use simple_logger;
use simple_logger::init_with_level;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use std::str;
use tempdir::TempDir;
use url::{ParseError, Url};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
struct Finding {
    //    branch: String, // this requires a walk of the commits for each finding, so lets leave it out for the moment
    commit: String,
    #[serde(rename = "commitHash")]
    commit_hash: String,
    date: String,
    diff: String,
    #[serde(rename = "stringsFound")]
    strings_found: Vec<String>,
    path: String,
    reason: String,
}

enum GitScheme {
    Localpath,
    Http,
    Ssh,
    Relativepath,
    Git
}

fn main() {
    let matches = clap_app!(choctaw_hog =>
        (version: "0.4.4")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "Git secret hunter in Rust")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file, defaults to ./trufflehog_rules.json")
        (@arg GITPATH: +required "Sets the path (or URL) of the Git repo to scan. SSH links must include username (git@)")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Output the JSON in human readable format")
        (@arg SINCECOMMIT: --since_commit +takes_value "Filters commits based on date committed (branch agnostic)")
        (@arg SSHKEYPATH: --sshkeypath +takes_value "Takes a path to a private SSH key for git authentication, defaults to ssh-agent")
        (@arg SSHKEYPHRASE: --sshkeyphrase +takes_value "Takes a passphrase to a private SSH key for git authentication, defaults to none")
    )
    .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => panic!("error: {}", e),
    }
}

fn get_ssh_git_repo(
    path: &str,
    dest_dir: &Path,
    arg_matches: &ArgMatches,
    username: &str,
) -> Repository {
    info!("username in get_ssh_git_repo: {:?}", username);
    let mut cb = git2::RemoteCallbacks::new();
    if arg_matches.is_present("SSHKEYPATH") {
        cb.credentials(|_, _, _| {
            info!("SSHKEYPATH detected, attempting to read credentials from supplied path...");
            let credentials = git2::Cred::ssh_key(
                username,
                None,
                Path::new(&arg_matches.value_of("SSHKEYPATH").unwrap()),
                arg_matches.value_of("SSHKEYPHRASE"),
            )
            .expect("Cannot create credentials object.");
            Ok(credentials)
        });
    } else {
        cb.credentials(|_, _, _| {
            info!("no SSHKEYPATH detected, attempting to read credentials from ssh_agent...");
            let credentials = git2::Cred::ssh_key_from_agent(username)
                .expect("Cannot create credentials object from ssh_agent");
            Ok(credentials)
        });
    }
    let mut fo = git2::FetchOptions::new();
    fo.remote_callbacks(cb);
    let mut builder = git2::build::RepoBuilder::new();
    builder.fetch_options(fo);
    info!("SSH Git credentials successfully initialized, attempting to clone the repo...");
    match builder.clone(path, dest_dir) {
        Ok(r) => r,
        Err(e) => panic!(
            "<GITPATH> {:?} is a SSH GIT URL but couldn't be cloned:\n{:?}",
            path, e
        ),
    }
}

fn get_git_repo(path: &str, dest_dir: &Path, arg_matches: &ArgMatches) -> Repository {
    let url = Url::parse(path);
    // try to figure out the format of the path
    let scheme: GitScheme = match &url {
        Ok(url) => match url.scheme().to_ascii_lowercase().as_ref() {
            "http" => {
                info!("Git scheme detected as http://, performing a clone...");
                GitScheme::Http
            }
            "https" => {
                info!("Git scheme detected as https:// , performing a clone...");
                GitScheme::Http
            }
            "file" => {
                info!("Git scheme detected as file://, performing a clone...");
                GitScheme::Localpath
            }
            "ssh" => {
                info!("Git scheme detected as ssh://, performing a clone...");
                GitScheme::Ssh
            }
            "git" => {
                info!("Git scheme detected as git://, performing a clone...");
                GitScheme::Git
            }
            s => panic!(
                "Error parsing GITPATH {:?}, please include the username with \"git@\"",
                s
            ),
        },
        Err(e) => match e {
            ParseError::RelativeUrlWithoutBase => {
                info!(
                    "Git scheme detected as a relative path, attempting to open on the local \
                     file system and then falling back to SSH..."
                );
                GitScheme::Relativepath
            }
            e => panic!("Unknown error parsing GITPATH: {:?}", e),
        },
    };

    match scheme {
        GitScheme::Localpath => match Repository::clone(path, dest_dir) {
            Ok(r) => r,
            Err(e) => panic!(
                "<GITPATH> {:?} was detected as a local path but couldn't be opened: {:?}",
                path, e
            ),
        },
        GitScheme::Http => match Repository::clone(path, dest_dir) {
            Ok(r) => r,
            Err(e) => panic!(
                "<GITPATH> {:?} is an HTTP(s) URL but couldn't be opened: {:?}",
                path, e
            ),
        },
        GitScheme::Git => {
            let url = url.unwrap(); // we already have assurance this passed successfully
            let username = match url.username() {
                "" => "git",
                s => s
            };
            get_ssh_git_repo(path, dest_dir, arg_matches, username)
        }
        GitScheme::Ssh => {
            let url = url.unwrap(); // we already have assurance this passed successfully
            let username = url.username();
            get_ssh_git_repo(path, dest_dir, arg_matches, username)
        }
        // since @ and : are valid characters in linux paths, we need to try both opening locally
        // and over SSH. This SSH syntax is normal for Github.
        GitScheme::Relativepath => match Repository::open(path) {
            //
            Ok(r) => r,
            Err(_) => {
                let username = match path.find('@') {
                    Some(i) => path.split_at(i).0,
                    None => "git",
                };
                get_ssh_git_repo(path, dest_dir, arg_matches, username)
            }
        },
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

    // Get Git objects
    let dest_dir = TempDir::new("rusty_hogs").unwrap();
    let dest_dir_path = dest_dir.path();
    let source_path: &str = arg_matches.value_of("GITPATH").unwrap();
    let repo = get_git_repo(source_path, &dest_dir_path, arg_matches);
    let mut revwalk = repo.revwalk().unwrap();
    revwalk.push_glob("*").unwrap(); //easy mode: iterate over all the commits
                                     // convert our iterator of OIDs to commit objects
    let revwalk = revwalk.map(|id| repo.find_commit(id.unwrap()));

    // Get regex objects
    let secret_scanner: SecretScanner = match arg_matches.value_of("REGEX") {
        Some(f) => SecretScanner::new_fromfile(f, arg_matches.is_present("CASE"))?,
        None => SecretScanner::new(arg_matches.is_present("CASE"))?,
    };
    let mut findings: HashSet<Finding> = HashSet::new();

    // setup a list of branches so we can annotate our findings with the branch name
    // (skipping for performance reasons... for now)
    //    let branch_iter = repo.branches(Ok(BranchType::Remote)).unwrap();
    //    let branch_collection: Vec<Branch> = branch_iter.collect();
    //    let branch_collection: Vec<(String, Reference)> = branch_collection.into_iter().map(|x| {
    //        (x.name().unwrap().unwrap().to_string(), x.into_reference())
    //    }).collect();

    // take our "--since_commit" input (hash id) and convert it to a date and time
    let since_time_obj: Time = if arg_matches.is_present("SINCECOMMIT") {
        let revspec = match repo.revparse(arg_matches.value_of("SINCECOMMIT").unwrap()) {
            Ok(r) => r,
            Err(e) => panic!("SINCECOMMIT value returned an error: {:?}", e),
        };
        let o = revspec.from().unwrap();
        o.as_commit().unwrap().time()
    } else {
        Time::new(0, 0)
    };

    // filter our commits: only commits that occured after the --since_commit filter using epoch math
    let revwalk = revwalk.filter(|c| c.as_ref().unwrap().time() >= since_time_obj);

    // The main loop - scan each line of each diff of each commit for regex matches
    for commit in revwalk {
        // based on https://github.com/alexcrichton/git2-rs/blob/master/examples/log.rs
        let commit = commit.unwrap();
        info!("Scanning commit {}", commit.id());
        if commit.parents().len() > 1 {
            continue;
        }
        let a = if commit.parents().len() == 1 {
            let parent = commit.parent(0).unwrap();
            Some(parent.tree().unwrap())
        } else {
            None
        };
        let b = commit.tree().unwrap();
        let mut diffopts = DiffOptions::new();
        diffopts.force_binary(true);

        let diff = repo
            .diff_tree_to_tree(a.as_ref(), Some(&b), Some(&mut diffopts))
            .unwrap();

        // secondary loop that occurs for each *line* in the diff
        diff.print(DiffFormat::Patch, |delta, _hunk, line| {
            let new_line = line.content();
            let matches_map: BTreeMap<&String, Matches> = secret_scanner.get_matches(new_line);

            for (reason, match_iterator) in matches_map {
                let mut secrets: Vec<String> = Vec::new();
                for matchobj in match_iterator {
                    secrets.push(
                        ASCII
                            .decode(
                                &new_line[matchobj.start()..matchobj.end()],
                                DecoderTrap::Ignore,
                            )
                            .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                    );
                }
                if !secrets.is_empty() {
                    findings.insert(Finding {
                        commit_hash: commit.id().to_string(),
                        commit: commit.message().unwrap().to_string(),
                        diff: ASCII
                            .decode(&new_line, DecoderTrap::Ignore)
                            .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                        date: NaiveDateTime::from_timestamp(commit.time().seconds(), 0).to_string(),
                        strings_found: secrets.clone(),
                        path: delta
                            .new_file()
                            .path()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                        reason: reason.clone(),
                    });
                }
            }

            if arg_matches.is_present("ENTROPY") {
                let ef = SecretScanner::get_entropy_findings(new_line);
                if !ef.is_empty() {
                    findings.insert(Finding {
                        commit: commit.message().unwrap().to_string(),
                        commit_hash: commit.id().to_string(),
                        diff: ASCII
                            .decode(&new_line, DecoderTrap::Ignore)
                            .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                        date: NaiveDateTime::from_timestamp(commit.time().seconds(), 0).to_string(),
                        strings_found: ef,
                        path: delta
                            .new_file()
                            .path()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                        reason: "Entropy".to_string(),
                    });
                }
            }
            true
        })
        .unwrap();
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

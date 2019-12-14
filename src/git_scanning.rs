//! Collection of tools for scanning Git repos for secrets.
//!
//! GitScanner acts as a wrapper around a SecretScanner object to provide helper functions for
//! performing scanning against Git repositories. Relies on the
//! [git2-rs](https://github.com/rust-lang/git2-rs) library which provides lower level access to
//! the Git data structures.
//!
//! # Examples
//!
//! Basic usage requires you to first create a secret scanner object and supply it to the
//! constructor:
//!
//! ```
//! use rusty_hogs::SecretScannerBuilder;
//! use rusty_hogs::git_scanning::GitScanner;
//! let ss = SecretScannerBuilder::new().build();
//! let gs = GitScanner::new(ss);
//! ```
//!
//! After that, you must first run init_git_repo(), then perform_scan(), which returns a HashSet
//! of findings...
//!
//! ```
//! use rusty_hogs::SecretScannerBuilder;
//! use rusty_hogs::git_scanning::{GitScanner, GitFinding};
//! use std::collections::HashSet;
//! use std::path::Path;
//!
//! let ss = SecretScannerBuilder::new().build();
//! let gs = GitScanner::new(ss);
//!
//! let mut gs = gs.init_git_repo(".", Path::new("."), None, None);
//! let findings: HashSet<GitFinding> = gs.perform_scan(None, None, false);
//! assert_eq!(findings.len(), 35);
//! ```

use crate::SecretScanner;
use chrono::NaiveDateTime;
use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use git2::{Commit, DiffFormat};
use git2::{DiffOptions, Repository, Time};
use log::{self, info};
use regex::bytes::Matches;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::str;
use url::{ParseError, Url};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
/// serde_json object that represents a single found secret - finding
pub struct GitFinding {
    //    branch: String, // this requires a walk of the commits for each finding, so lets leave it out for the moment
    pub commit: String,
    #[serde(rename = "commitHash")]
    pub commit_hash: String,
    pub date: String,
    pub diff: String,
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub path: String,
    pub reason: String,
}

/// enum used by init_git_repo to communicate the type of git repo specified by the supplied URL
pub enum GitScheme {
    Localpath,
    Http,
    Ssh,
    Relativepath,
    Git,
}

/// Contains helper functions for performing scans of Git repositories
pub struct GitScanner {
    pub secret_scanner: SecretScanner,
    pub repo: Option<Repository>,
    pub scheme: Option<GitScheme>,
}

impl GitScanner {
    /// Initialize the SecretScanner object first using the SecretScannerBuilder, then provide
    /// it to this constructor method.
    pub fn new(secret_scanner: SecretScanner) -> GitScanner {
        GitScanner {
            secret_scanner,
            repo: None,
            scheme: None,
        }
    }

    /// Uses the GitScanner object to return a HashSet of findings from that repository
    pub fn perform_scan(
        &self,
        glob: Option<&str>,
        since_commit: Option<&str>,
        scan_entropy: bool,
    ) -> HashSet<GitFinding> {
        let repo_option = self.repo.as_ref(); //borrowing magic here!
        let repo = repo_option.unwrap();
        let mut revwalk = repo.revwalk().unwrap();
        revwalk.push_glob(glob.unwrap_or_else(|| "*")).unwrap(); //easy mode: iterate over all the commits

        // take our "--since_commit" input (hash id) and convert it to a date and time
        // and build our revwalk with a filter for commits >= that time. This isn't a perfect
        // method since it might get confused about merges, but it has the added benefit of
        // including orphaned branches and commits in unrelated branches.
        let since_time_obj: Time = match since_commit {
            Some(sc) => {
                let revspec = match repo.revparse(sc) {
                    Ok(r) => r,
                    Err(e) => panic!("SINCECOMMIT value returned an error: {:?}", e),
                };
                let o = revspec.from().unwrap();
                o.as_commit().unwrap().time()
            }
            None => Time::new(0, 0),
        };

        // convert our iterator of OIDs to an iterator of commit objects filtered by commit date
        let revwalk = revwalk
            .map(|id| repo.find_commit(id.unwrap()))
            .filter(|c| c.as_ref().unwrap().time() >= since_time_obj);

        let mut findings: HashSet<GitFinding> = HashSet::new();
        // The main loop - scan each line of each diff of each commit for regex matches
        for commit in revwalk {
            // based on https://github.com/alexcrichton/git2-rs/blob/master/examples/log.rs
            let commit: Commit = commit.unwrap();
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
                let matches_map: BTreeMap<&String, Matches> =
                    self.secret_scanner.get_matches(new_line);

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
                        findings.insert(GitFinding {
                            commit_hash: commit.id().to_string(),
                            commit: commit.message().unwrap().to_string(),
                            diff: ASCII
                                .decode(&new_line, DecoderTrap::Ignore)
                                .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                            date: NaiveDateTime::from_timestamp(commit.time().seconds(), 0)
                                .to_string(),
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

                if scan_entropy {
                    let ef = SecretScanner::get_entropy_findings(new_line);
                    if !ef.is_empty() {
                        findings.insert(GitFinding {
                            commit: commit.message().unwrap().to_string(),
                            commit_hash: commit.id().to_string(),
                            diff: ASCII
                                .decode(&new_line, DecoderTrap::Ignore)
                                .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                            date: NaiveDateTime::from_timestamp(commit.time().seconds(), 0)
                                .to_string(),
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
        findings
    }

    fn get_https_git_repo(
        https_git_url: &str,
        dest_dir: &Path,
        httpsuser: &str,
        httpspass: &str,
    ) -> Repository {
        let mut cb = git2::RemoteCallbacks::new();

        cb.credentials(|_, _, _| {
            info!("HTTPS auth detected, attempting to create credentials object...");
            let credentials = git2::Cred::userpass_plaintext(httpsuser, httpspass)
                .expect("Cannot create credentials object.");
            Ok(credentials)
        });

        let mut fo = git2::FetchOptions::new();
        fo.remote_callbacks(cb);
        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(fo);
        info!("HTTPS Git credentials successfully initialized, attempting to clone the repo...");
        match builder.clone(https_git_url, dest_dir) {
            Ok(r) => r,
            Err(e) => panic!(
                "<GITPATH> {:?} is a HTTPS GIT URL but couldn't be cloned. If your GitHub account \
                 uses 2FA make sure to use a personal access token as your password!:\n{:?}",
                https_git_url, e
            ),
        }
    }

    fn get_ssh_git_repo(
        ssh_git_url: &str,
        dest_dir: &Path,
        sshkeypath: Option<&str>,
        sshkeyphrase: Option<&str>,
        username: &str,
    ) -> Repository {
        info!("username in get_ssh_git_repo: {:?}", username);
        let mut cb = git2::RemoteCallbacks::new();
        if sshkeypath.is_some() {
            cb.credentials(|_, _, _| {
                info!("SSHKEYPATH detected, attempting to read credentials from supplied path...");
                let credentials = git2::Cred::ssh_key(
                    username,
                    None,
                    Path::new(sshkeypath.unwrap()),
                    sshkeyphrase,
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
        match builder.clone(ssh_git_url, dest_dir) {
            Ok(r) => r,
            Err(e) => panic!(
                "<GITPATH> {:?} is a SSH GIT URL but couldn't be cloned:\n{:?}",
                ssh_git_url, e
            ),
        }
    }

    /// Initialize a [Repository](https://docs.rs/git2/0.10.2/git2/struct.Repository.html) object
    pub fn init_git_repo(
        mut self,
        path: &str,
        dest_dir: &Path,
        sshkeypath: Option<&str>,
        sshkeyphrase: Option<&str>,
        httpsuser: Option<&str>,
        httpspass: Option<&str>,
    ) -> GitScanner {
        let url = Url::parse(path);
        // try to figure out the format of the path
        self.scheme = match &url {
            Ok(url) => match url.scheme().to_ascii_lowercase().as_ref() {
                "http" => {
                    info!("Git scheme detected as http://, performing a clone...");
                    Some(GitScheme::Http)
                }
                "https" => {
                    info!("Git scheme detected as https:// , performing a clone...");
                    Some(GitScheme::Http)
                }
                "file" => {
                    info!("Git scheme detected as file://, performing a clone...");
                    Some(GitScheme::Localpath)
                }
                "ssh" => {
                    info!("Git scheme detected as ssh://, performing a clone...");
                    Some(GitScheme::Ssh)
                }
                "git" => {
                    info!("Git scheme detected as git://, performing a clone...");
                    Some(GitScheme::Git)
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
                    Some(GitScheme::Relativepath)
                }
                e => panic!("Unknown error parsing GITPATH: {:?}", e),
            },
        };

        self.repo = match self.scheme {
            None => panic!("Git scheme not detected?"),
            Some(GitScheme::Localpath) => match Repository::clone(path, dest_dir) {
                Ok(r) => Some(r),
                Err(e) => panic!(
                    "<GITPATH> {:?} was detected as a local path but couldn't be opened: {:?}",
                    path, e
                ),
            },
            Some(GitScheme::Http) => {
                let httpsuser = match httpsuser {
                    Some(s) => s,
                    None => panic!("HTTPS GIT URL detected but no username supplied"),
                };
                let httpspass = match httpspass {
                    Some(s) => s,
                    None => panic!("HTTPS GIT URL detected but no password supplied"),
                };
                Some(GitScanner::get_https_git_repo(
                    path, dest_dir, httpsuser, httpspass,
                ))
            }
            Some(GitScheme::Git) => {
                let url = url.unwrap(); // we already have assurance this passed successfully
                let username = match url.username() {
                    "" => "git",
                    s => s,
                };
                Some(GitScanner::get_ssh_git_repo(
                    path,
                    dest_dir,
                    sshkeypath,
                    sshkeyphrase,
                    username,
                ))
            }
            Some(GitScheme::Ssh) => {
                let url = url.unwrap(); // we already have assurance this passed successfully
                let username = url.username();
                Some(GitScanner::get_ssh_git_repo(
                    path,
                    dest_dir,
                    sshkeypath,
                    sshkeyphrase,
                    username,
                ))
            }
            // since @ and : are valid characters in linux paths, we need to try both opening locally
            // and over SSH. This SSH syntax is normal for Github.
            Some(GitScheme::Relativepath) => match Repository::open(path) {
                //
                Ok(r) => Some(r),
                Err(_) => {
                    let username = match path.find('@') {
                        Some(i) => path.split_at(i).0,
                        None => "git",
                    };
                    Some(GitScanner::get_ssh_git_repo(
                        path,
                        dest_dir,
                        sshkeypath,
                        sshkeyphrase,
                        username,
                    ))
                }
            },
        };
        self
    }
}

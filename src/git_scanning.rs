//! Collection of tools for scanning Git repos for secrets.
//!
//! `GitScanner` acts as a wrapper around a `SecretScanner` object to provide helper functions for
//! performing scanning against Git repositories. Relies on the
//! [git2-rs](https://github.com/rust-lang/git2-rs) library which provides lower level access to
//! the Git data structures.
//!
//! # Examples
//!
//! Basic usage requires you to create a `GitScanner` object...
//!
//! ```
//! use rusty_hog_scanner::SecretScannerBuilder;
//! use rusty_hogs::git_scanning::GitScanner;
//! let gs = GitScanner::new();
//! ```
//!
//! Alternatively you can build a custom `SecretScanner` object and supply it to the `GitScanner`
//! contructor...
//!
//! ```
//! use rusty_hog_scanner::SecretScannerBuilder;
//! use rusty_hogs::git_scanning::GitScanner;
//! let ss = SecretScannerBuilder::new().set_pretty_print(true).build();
//! let gs = GitScanner::new_from_scanner(ss);
//! ```
//!
//! After that, you must first run `init_git_repo()`, then `perform_scan()`, which returns a
//! `HashSet` of findings. In this example we're specifying a specific commit to stop scanning at
//! (801360e) so we can have a reliable result.
//!
//! ```
//! use rusty_hog_scanner::SecretScannerBuilder;
//! use rusty_hogs::git_scanning::{GitScanner, GitFinding};
//! use std::collections::HashSet;
//! use std::path::Path;
//!
//! let gs = GitScanner::new();
//!
//! let mut gs = gs.init_git_repo(".", Path::new("."), None, None, None, None);
//! let findings: HashSet<GitFinding> = gs.perform_scan(None, Some("7e8c52a"), Some("8013160e"), None);
//! assert_eq!(findings.len(), 8);
//! ```

use chrono::NaiveDateTime;
use chrono::Utc;
use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use git2::{Commit, DiffFormat, Tree};
use git2::{DiffOptions, Repository, Time};
use log::{self, debug, info};
use rusty_hog_scanner::{RustyHogMatch, SecretScanner};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::{fmt, str};
use url::{ParseError, Url};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
/// `serde_json` object that represents a single found secret - finding
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
    pub old_file_id: String,
    pub new_file_id: String,
    pub old_line_num: u32,
    pub new_line_num: u32,
    pub parent_commit_hash: String,
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
    pub fn new_from_scanner(secret_scanner: SecretScanner) -> Self {
        Self {
            secret_scanner,
            repo: None,
            scheme: None,
        }
    }

    pub fn new() -> Self {
        Self {
            secret_scanner: SecretScanner::default(),
            repo: None,
            scheme: None,
        }
    }

    /// Uses the GitScanner object to return a HashSet of findings from that repository
    pub fn perform_scan(
        &self,
        glob: Option<&str>,
        since_commit: Option<&str>,
        until_commit: Option<&str>,
        recent_days: Option<u32>,
    ) -> HashSet<GitFinding> {
        let repo_option = self.repo.as_ref(); //borrowing magic here!
        let repo = repo_option.unwrap();
        let mut revwalk = repo.revwalk().unwrap();
        revwalk.push_glob(glob.unwrap_or("*")).unwrap(); //easy mode: iterate over all the commits

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
                // println!("{:?}", o.as_commit().unwrap());
                o.as_commit().unwrap().time()
            }
            None => match recent_days {
                Some(rd) => Time::new(Utc::now().timestamp() - (rd as i64 * 24 * 60 * 60), 0),
                None => Time::new(0, 0),
            },
        };

        let until_time_obj: Time = match until_commit {
            Some(sc) => {
                let revspec = match repo.revparse(sc) {
                    Ok(r) => r,
                    Err(e) => panic!("UNTILCOMMIT value returned an error: {:?}", e),
                };
                let o = revspec.from().unwrap();
                o.as_commit().unwrap().time()
            }
            None => Time::new(i64::max_value(), 0),
        };

        // convert our iterator of OIDs to an iterator of commit objects filtered by commit date
        let revwalk = revwalk.map(|id| repo.find_commit(id.unwrap())).filter(|c| {
            c.as_ref().unwrap().time() >= since_time_obj
                && c.as_ref().unwrap().time() <= until_time_obj
        });

        let mut findings: HashSet<GitFinding> = HashSet::new();
        // The main loop - scan each line of each diff of each commit for regex matches
        for commit in revwalk {
            // based on https://github.com/alexcrichton/git2-rs/blob/master/examples/log.rs
            let commit: Commit = commit.unwrap();
            info!("Scanning commit {}", commit.id());
            if commit.parents().len() > 1 {
                continue;
            }
            let parent_commit_option = if commit.parents().len() == 1 {
                Some(commit.parent(0).unwrap())
            } else {
                None
            };
            let parent_commit_hash: String = match parent_commit_option.as_ref() {
                Some(pc) => pc.id().to_string(),
                None => String::from("None"),
            };
            let a: Option<Tree> = match parent_commit_option {
                Some(pc) => Some(pc.tree().unwrap()),
                _ => None,
            };
            let b = commit.tree().unwrap();
            let mut diffopts = DiffOptions::new();
            diffopts.force_text(true);
            // diffopts.show_binary(true);
            diffopts.context_lines(0);

            let diff = repo
                .diff_tree_to_tree(a.as_ref(), Some(&b), Some(&mut diffopts))
                .unwrap();

            // secondary loop that occurs for each *line* in the diff
            diff.print(DiffFormat::Patch, |delta, _hunk, line| {
                if line.origin() == 'F' || line.origin() == 'H' {
                    return true;
                };
                let new_line = line.content();
                // debug!("new_line: {:?}",String::from_utf8_lossy(new_line));
                let matches_map: BTreeMap<String, Vec<RustyHogMatch>> =
                    self.secret_scanner.matches_entropy(new_line);
                if matches_map.contains_key("Entropy") {
                    debug!("Entropy finding");
                }
                let old_file_id = delta.old_file().id();
                let new_file_id = delta.new_file().id();
                let old_line_num = line.old_lineno().unwrap_or(0);
                let new_line_num = line.new_lineno().unwrap_or(0);

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
                        let path = delta
                            .new_file()
                            .path()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string();
                        let enough_entropy = self.secret_scanner.check_entropy(&reason, new_line);
                        let valid_path = !self
                            .secret_scanner
                            .is_allowlisted_path(&reason, path.as_bytes());
                        if enough_entropy && valid_path {
                            findings.insert(GitFinding {
                                commit_hash: commit.id().to_string(),
                                commit: commit.message().unwrap().to_string(),
                                diff: ASCII
                                    .decode(&new_line, DecoderTrap::Ignore)
                                    .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                                date: NaiveDateTime::from_timestamp(commit.time().seconds(), 0)
                                    .to_string(),
                                strings_found: secrets.clone(),
                                path,
                                reason: reason.clone(),
                                old_file_id: old_file_id.to_string(),
                                new_file_id: new_file_id.to_string(),
                                old_line_num,
                                new_line_num,
                                parent_commit_hash: parent_commit_hash.clone(),
                            });
                        }
                    }
                }
                true
            })
            .unwrap();
        }
        findings
    }

    /// Helper function to return a
    /// [`Repository`](https://docs.rs/git2/0.11.0/git2/struct.Repository.html) object for HTTPS
    /// URLs and credentials. Used by `init_git_repo`
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

    /// Helper function to return a
    /// [`Repository`](https://docs.rs/git2/0.11.0/git2/struct.Repository.html) object for SSH
    /// URLs and credentials. Used by `init_git_repo`
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
    ) -> Self {
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
                Some(Self::get_https_git_repo(
                    path, dest_dir, httpsuser, httpspass,
                ))
            }
            Some(GitScheme::Git) => {
                let url = url.unwrap(); // we already have assurance this passed successfully
                let username = match url.username() {
                    "" => "git",
                    s => s,
                };
                Some(Self::get_ssh_git_repo(
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
                Some(Self::get_ssh_git_repo(
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
                    Some(Self::get_ssh_git_repo(
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

impl fmt::Debug for GitScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repo_str = match self.repo.as_ref() {
            None => "None",
            Some(repo_obj) => repo_obj.path().to_str().unwrap_or("<path unwrap error>"),
        };
        write!(
            f,
            "GitScanner: SecretScanner: {:?}, Repo: {:?}, GitScheme: {:?}",
            self.secret_scanner, repo_str, self.scheme
        )
    }
}

impl fmt::Display for GitScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repo_str = match self.repo.as_ref() {
            None => "None",
            Some(repo_obj) => repo_obj.path().to_str().unwrap_or("<path unwrap error>"),
        };
        let scheme_string: String = match self.scheme.as_ref() {
            None => String::from("None"),
            Some(s) => fmt::format(format_args!("{}", s)),
        };
        write!(
            f,
            "GitScanner: SecretScanner: {}, Repo: {}, GitScheme: {}",
            self.secret_scanner, repo_str, &scheme_string
        )
    }
}

impl fmt::Debug for GitScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_string = match self {
            GitScheme::Localpath => "localpath",
            GitScheme::Http => "http",
            GitScheme::Ssh => "ssh",
            GitScheme::Relativepath => "relativepath",
            GitScheme::Git => "git",
        };
        write!(f, "GitScheme: {}", display_string)
    }
}

impl fmt::Display for GitScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_string = match self {
            GitScheme::Localpath => "localpath",
            GitScheme::Http => "http",
            GitScheme::Ssh => "ssh",
            GitScheme::Relativepath => "relativepath",
            GitScheme::Git => "git",
        };
        write!(f, "GitScheme: {}", display_string)
    }
}

impl PartialEq for GitScheme {
    fn eq(&self, other: &Self) -> bool {
        format!("{}", self) == format!("{}", other)
    }
}

impl Eq for GitScheme {}

impl PartialEq for GitScanner {
    fn eq(&self, other: &Self) -> bool {
        self.secret_scanner == other.secret_scanner
            && match self.scheme.as_ref() {
                None => other.scheme.is_none(),
                Some(gs) => match other.scheme.as_ref() {
                    None => false,
                    Some(gs2) => *gs == *gs2,
                },
            }
            && match self.repo.as_ref() {
                None => other.repo.is_none(),
                Some(r) => match other.repo.as_ref() {
                    None => false,
                    Some(r2) => r.path() == r2.path(),
                },
            }
    }
}

impl Eq for GitScanner {}

impl Hash for GitScanner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.secret_scanner.hash(state);
        match self.repo.as_ref() {
            None => "norepo".hash(state),
            Some(r) => r.path().hash(state),
        };
        match self.scheme.as_ref() {
            None => "noscheme".hash(state),
            Some(gs) => match gs {
                GitScheme::Localpath => "localpath".hash(state),
                GitScheme::Http => "http".hash(state),
                GitScheme::Ssh => "ssh".hash(state),
                GitScheme::Relativepath => "relativepath".hash(state),
                GitScheme::Git => "git".hash(state),
            },
        }
    }
}

impl Default for GitScanner {
    fn default() -> Self {
        Self::new()
    }
}

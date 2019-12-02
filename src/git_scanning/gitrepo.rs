use crate::SecretScanner;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
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

pub enum GitScheme {
    Localpath,
    Http,
    Ssh,
    Relativepath,
    Git
}

/// Contains helper functions for performing scans of Git repositories
pub struct GitScanner {
    pub secret_scanner: SecretScanner
}

/// Acts as a wrapper around a SecretScanner object to provide helper functions for performing
/// scanning against Git repositories. Relies on the [git2-rs](https://github.com/rust-lang/git2-rs)
/// library which provides lower level access to the Git data structures.
impl GitScanner {
    /// Initialize the SecretScanner object first using the SecretScannerBuilder, then provide
    /// it to this constructor method.
    pub fn new(secret_scanner: SecretScanner) -> GitScanner {
        GitScanner { secret_scanner }
    }
}
//! Collection of tools for scanning Google Suite for secrets. Currently only supports Google Drive.

use crate::SecretScanner;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct GDriveFinding {
    pub date: String,
    pub diff: String,
    pub path: String,
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub g_drive_id: String,
    pub reason: String,
    pub web_link: String
}

/// Contains helper functions for performing scans of Google Drive objects
pub struct GDriveScanner {
    pub secret_scanner: SecretScanner
}

/// Acts as a wrapper around a SecretScanner object to provide helper functions for performing
/// scanning against Google Drive files. Relies on the [google_drive3](https://docs.rs/google-drive3/1.0.10+20190620/google_drive3/)
/// library which provides a wrapper around the Google Drive v3 API.
impl GDriveScanner {
    /// Initialize the SecretScanner object first using the SecretScannerBuilder, then provide
    /// it to this constructor method.
    pub fn new(secret_scanner: SecretScanner) -> GDriveScanner {
        GDriveScanner { secret_scanner }
    }
}
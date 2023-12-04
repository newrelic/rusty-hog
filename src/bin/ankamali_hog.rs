//! Google Drive secret scanner in Rust
//!
//! # Usage
//! ```text
//! ankamali_hog [FLAGS] [OPTIONS] <GDRIVEID>
//!
//!FLAGS:
//!         --caseinsensitive    Sets the case insensitive flag for all regexes
//!         --entropy            Enables entropy scanning
//!         --oauthsecret        Path to an OAuth secret file (JSON) ./clientsecret.json by default
//!         --oauthtoken         Path to an OAuth token storage file ./temp_token by default
//!         --prettyprint        Output the JSON in human readable format
//!     -v, --verbose            Sets the level of debugging information
//!     -h, --help               Prints help information
//!     -V, --version            Prints version information
//!
//!OPTIONS:
//!        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
//!    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
//!        --regex <REGEX>          Sets a custom regex JSON file
//!
//!ARGS:
//!    <GDRIVEID>    The ID of the google drive file you want to scan
//! ```

extern crate clap;
extern crate google_drive3 as drive3;
extern crate hyper;
extern crate hyper_rustls;
extern crate yup_oauth2 as oauth2;

use clap::{Arg, ArgAction, ArgMatches, Command};
use drive3::DriveHub;
use log::{self, error, info};
use simple_error::SimpleError;
use std::path::Path;
use rusty_hogs::google_scanning::{GDriveFileInfo, GDriveScanner};
use rusty_hog_scanner::{SecretScanner, SecretScannerBuilder};
use oauth2::{InstalledFlowAuthenticator, InstalledFlowReturnMethod};

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
#[tokio::main]
async fn main() {
    let matches = Command::new("ankamali_hog")
        .version("1.0.11")
        .author("Scott Cutler <scutler@newrelic.com>")
        .about("Google Drive secret scanner in Rust.")
        .arg(Arg::new("REGEX").long("regex").action(ArgAction::Set).help("Sets a custom regex JSON file"))
        .arg(Arg::new("GDRIVEID").required(true).action(ArgAction::Set).help("The ID of the Google drive file you want to scan"))
        .arg(Arg::new("VERBOSE").short('v').long("verbose").action(ArgAction::Count).help("Sets the level of debugging information"))
        .arg(Arg::new("ENTROPY").long("entropy").action(ArgAction::SetTrue).help("Enables entropy scanning"))
        .arg(Arg::new("DEFAULT_ENTROPY_THRESHOLD").long("default_entropy_threshold").action(ArgAction::Set).help("Default entropy threshold (0.6 by default)"))
        .arg(Arg::new("CASE").long("caseinsensitive").action(ArgAction::SetTrue).help("Sets the case insensitive flag for all regexes"))
        .arg(Arg::new("OUTPUT").short('o').long("outputfile").action(ArgAction::Set).help("Sets the path to write the scanner results to (stdout by default)"))
        .arg(Arg::new("PRETTYPRINT").long("prettyprint").action(ArgAction::SetTrue).help("Outputs the JSON in human readable format"))
        .arg(Arg::new("OAUTHSECRETFILE").long("oauthsecret").action(ArgAction::Set).default_value("./clientsecret.json").help("Path to an OAuth secret file (JSON) ./clientsecret.json by default"))
        .arg(Arg::new("OAUTHTOKENFILE").long("oauthtoken").action(ArgAction::Set).default_value("./temp_token").help("Path to an OAuth token storage file ./temp_token by default"))
        .arg(Arg::new("ALLOWLIST").short('a').long("allowlist").action(ArgAction::Set).help("Sets a custom allowlist JSON file"))
        .get_matches();
    match run(matches).await {
        Ok(()) => {}
        Err(e) => error!("Error running command: {}", e),
    }
}

/// Main logic contained here. Get the CLI variables, setup OAuth, setup GDriveScanner and output
/// the results.
async fn run(arg_matches: ArgMatches) -> Result<(), SimpleError> {    // Set logging
    SecretScanner::set_logging(arg_matches.get_count("VERBOSE").into());

    // Initialize some variables
    let oauthsecretfile = arg_matches
        .get_one::<String>("OAUTHSECRETFILE")
        .map(|s| s.as_str())
        .unwrap_or("clientsecret.json");
    let oauthtokenfile = arg_matches
        .get_one::<String>("OAUTHTOKENFILE")
        .map(|s| s.as_str())
        .unwrap_or("temp_token");
    let file_id = arg_matches.get_one::<String>("GDRIVEID").unwrap();
    let secret_scanner = SecretScannerBuilder::new().conf_argm(&arg_matches).build();
    let gdrive_scanner = GDriveScanner::new_from_scanner(secret_scanner);

    // Start with GDrive auth - based on example code from drive3 API and yup-oauth2
    let secret = yup_oauth2::read_application_secret(Path::new(oauthsecretfile))
        .await
        .expect(oauthsecretfile);
    let auth = InstalledFlowAuthenticator::builder(secret, InstalledFlowReturnMethod::HTTPRedirect)
        .persist_tokens_to_disk(Path::new(oauthtokenfile))
        .build()
        .await
        .expect("failed to create authenticator (try deleting temp_token and restarting)");
    let hub = DriveHub::new(hyper::Client::builder().build(hyper_rustls::HttpsConnector::with_native_roots()), auth);

    // get some initial info about the file
    let gdriveinfo = GDriveFileInfo::new(file_id, &hub).await.unwrap();

    // Do the scan
    let findings = gdrive_scanner.perform_scan(&gdriveinfo, &hub).await;
    info!("Found {} secrets", findings.len());
    match gdrive_scanner.secret_scanner.output_findings(&findings) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with(
            "failed to output findings",
            SimpleError::new(err.to_string()),
        )),
    }
}

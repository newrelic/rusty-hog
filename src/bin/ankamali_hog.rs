//! Google Drive secret scanner in Rust
//!
//! # Usage
//! ```text
//! ankamali_hog [FLAGS] [OPTIONS] <GDRIVEID>
//!
//!FLAGS:
//!        --caseinsensitive    Sets the case insensitive flag for all regexes
//!        --entropy            Enables entropy scanning
//!        --prettyprint        Output the JSON in human readable format
//!    -v, --verbose            Sets the level of debugging information
//!    -h, --help               Prints help information
//!    -V, --version            Prints version information
//!
//!OPTIONS:
//!    -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
//!        --regex <REGEX>          Sets a custom regex JSON file
//!
//!ARGS:
//!    <GDRIVEID>    The ID of the google drive file you want to scan
//! ```

#[macro_use]
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;
extern crate yup_oauth2 as oauth2;
extern crate google_drive3 as drive3;

use clap::ArgMatches;
use simple_error::SimpleError;
use oauth2::{Authenticator, DefaultAuthenticatorDelegate, ApplicationSecret, FlowType, DiskTokenStorage};
use drive3::{DriveHub, Scope};
use std::collections::HashSet;
use log::{self, info};
use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use std::io::Read;
use std::path::Path;

use rusty_hogs::google_scanning::{GDriveFinding};
use rusty_hogs::{SecretScanner, SecretScannerBuilder};
use std::iter::FromIterator;

fn main() {
    let matches = clap_app!(ankamali_hog =>
        (version: "0.4.5")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "Google Drive secret scanner in Rust.")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file")
        (@arg GDRIVEID: +required "The ID of the google drive file you want to scan")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Output the JSON in human readable format")
        (@arg OAUTHSECRETFILE: --oauthsecret "Path to an OAuth secret file (JSON) ./clientsecret.json by default")
        (@arg OAUTHTOKENFILE: --oauthtoken "Path to an OAuth token storage file ./temp_token by default")
    )
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => panic!("error: {}", e),
    }
}

fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    // Set logging
    SecretScanner::set_logging(arg_matches.occurrences_of("VERBOSE"));

    // Initialize some variables
    let oauthsecretfile = arg_matches.value_of("OAUTHSECRETFILE").unwrap_or_else(|| "clientsecret.json");
    let oauthtokenfile =  arg_matches.value_of("OAUTHTOKENFILE").unwrap_or_else(|| "temp_token");
    let fileid = arg_matches.value_of("GDRIVEID").unwrap();
    let scan_entropy = arg_matches.is_present("ENTROPY");
    let prettyprint = arg_matches.is_present("PRETTYPRINT");
    let output_path = arg_matches.value_of("OUTPUT");

    // Start with GDrive auth - based on example code from drive3 API and yup-oauth2
    let secret: ApplicationSecret =  yup_oauth2::read_application_secret(Path::new(oauthsecretfile))
        .expect(oauthsecretfile);
    let token_storage = DiskTokenStorage::new(&String::from(oauthtokenfile)).unwrap();
    let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
                                      hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
                                      token_storage, Some(FlowType::InstalledInteractive));
    let hub = DriveHub::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);

    // get some initial info about the file
    let fields = "kind, id, name, mimeType, webViewLink, modifiedTime, parents";
    let hub_result = hub.files().get(fileid).add_scope(Scope::Readonly).param("fields",fields).doit();
    let (_,file_object) = match hub_result {
        Ok(x) => x,
        Err(e) => return Err(SimpleError::new(format!("failed accessing Google Metadata API {:?}", e)))
    };

    // initialize some variables from the response
    let modified_time = file_object.modified_time.unwrap().clone();
    let web_link = file_object.web_view_link.unwrap();
    let parents = file_object.parents.unwrap_or_else(Vec::new); //TODO: add code to map from id -> name
    let name = file_object.name.unwrap();
    let path = format!("{}/{}", parents.join("/"), name);
    let mime_type = match file_object.mime_type.unwrap().as_ref() {
        "application/vnd.google-apps.spreadsheet" => "text/csv", //TODO: Support application/x-vnd.oasis.opendocument.spreadsheet https://github.com/tafia/calamine
        "application/vnd.google-apps.document" => "text/plain",
        u => return Err(SimpleError::new(format!("unknown doc type {}", u)))
    };

    // download an export of the file, split on new lines, store in lines
    let resp_obj = hub.files().export(fileid, mime_type).doit();
    let mut resp_obj= match resp_obj {
        Ok(r) => r,
        Err(e) => return Err(SimpleError::new(e.to_string()))
    };
    let mut buffer: Vec<u8> = Vec::new();
    match resp_obj.read_to_end(&mut buffer) {
        Err(e) => return Err(SimpleError::new(e.to_string())),
        Ok(s) => s
    };
    let lines = buffer.split(|x| (*x as char) == '\n');

    // Get regex objects
    let secret_scanner = SecretScannerBuilder::new().conf_argm(arg_matches).build();

    // main loop - search each line for secrets, output a list of GDriveFinding objects
    let mut findings: HashSet<GDriveFinding> = HashSet::new();
    for new_line in lines {
        let matches_map = secret_scanner.get_matches(&new_line);
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
                findings.insert(GDriveFinding {
                    diff: ASCII
                        .decode(&new_line, DecoderTrap::Ignore)
                        .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                    date: modified_time.clone(),
                    strings_found: secrets.clone(),
                    reason: reason.clone(),
                    g_drive_id: fileid.to_string(),
                    path: path.clone(),
                    web_link: web_link.clone()
                });
            }
        }

        if scan_entropy {
            let ef = SecretScanner::get_entropy_findings(new_line);
            if !ef.is_empty() {
                findings.insert(GDriveFinding {
                    diff: ASCII
                        .decode(&new_line, DecoderTrap::Ignore)
                        .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                    date: modified_time.clone(),
                    strings_found: ef,
                    reason: "Entropy".parse().unwrap(),
                    g_drive_id: fileid.to_string(),
                    path: path.clone(),
                    web_link: web_link.clone()
                });
            }
        }
    }


    let findings: HashSet<GDriveFinding> = HashSet::from_iter(findings.into_iter());
    info!("Found {} secrets", findings.len());
    SecretScanner::output_findings(&findings, prettyprint, output_path);

    Ok(())
}
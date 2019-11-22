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
use std::{fs, str};
use secret_scanning::{SecretScanner};
use std::collections::HashSet;
use serde_derive::{Deserialize, Serialize};
use log::{self, info};
use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use std::io::Read;
use std::path::Path;
use simple_logger::init_with_level;


#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
struct GDriveFinding {
    date: String,
    diff: String,
    path: String,
    #[serde(rename = "stringsFound")]
    strings_found: Vec<String>,
    g_drive_id: String,
    reason: String,
    web_link: String
}

fn main() {
    let matches = clap_app!(ankamali_hog =>
        (version: "0.4.4")
        (author: "Scott Cutler <scutler@newrelic.com>")
        (about: "Google Drive secret hunter in Rust.")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file")
        (@arg GDRIVEID: +required "The ID of the google drive file you want to scan")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Output the JSON in human readable format")
    )
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => panic!("error: {}", e),
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

    // Start with GDrive auth - based on example code from drive3 API and yup-oauth2
    let secret: ApplicationSecret =  yup_oauth2::read_application_secret(Path::new("clientsecret.json"))
        .expect("clientsecret.json");
    let token_storage = DiskTokenStorage::new(&String::from("temp_token")).unwrap();
    let auth = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
                                      hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())),
                                      token_storage, Some(FlowType::InstalledInteractive));
//    let token = auth.token(&["https://www.googleapis.com/auth/drive.readonly"]).unwrap();

    let hub = DriveHub::new(hyper::Client::with_connector(hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())), auth);

    // get some initial info about the file
    let fields = "kind, id, name, mimeType, webViewLink, modifiedTime, parents";
    let fileid = arg_matches.value_of("GDRIVEID").unwrap();
    let hub_result = hub.files().get(fileid).add_scope(Scope::Readonly).param("fields",fields).doit();
    let (_,file_object) = match hub_result {
        Ok(x) => x,
        Err(e) => return Err(SimpleError::new(format!("failed accessing Google Metadata API {:?}", e)))
    };

    // initialize some variables from the response
    let modified_time = file_object.modified_time.unwrap().clone();
    let web_link = file_object.web_view_link.unwrap();
    let parents = file_object.parents.unwrap(); //TODO: add code to map from id -> name
    let name = file_object.name.unwrap();
    let path = format!("{}/{}", parents.join("/"), name);
    let mime_type = match file_object.mime_type.unwrap().as_ref() {
        "application/vnd.google-apps.spreadsheet" => "text/csv", //TODO: Support application/x-vnd.oasis.opendocument.spreadsheet https://github.com/tafia/calamine
        "application/vnd.google-apps.document" => "text/plain",
        u => return Err(SimpleError::new(format!("unknown doc type {}", u)))
    };

    // download an export of the file, split on new lines, store in lines
    let mut resp_obj = hub.files().export(fileid, mime_type).doit().unwrap();
    let mut buffer: Vec<u8> = Vec::new();
    match resp_obj.read_to_end(&mut buffer) {
        Err(e) => return Err(SimpleError::new(e.to_string())),
        Ok(s) => s
    };
    let lines = buffer.split(|x| (*x as char) == '\n');


    // Get regex objects
    let secret_scanner: SecretScanner = match arg_matches.value_of("REGEX") {
        Some(f) => SecretScanner::new_fromfile(f, arg_matches.is_present("CASE"))?,
        None => SecretScanner::new(arg_matches.is_present("CASE"))?,
    };

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

        if arg_matches.is_present("ENTROPY") {
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
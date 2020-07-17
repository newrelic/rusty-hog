//! Confluence secret scanner in Rust.
//!
//! USAGE:
//!     essex_hog [FLAGS] [OPTIONS] <PAGEID> <URL>
//!
//! FLAGS:
//!         --caseinsensitive    Sets the case insensitive flag for all regexes
//!         --entropy            Enables entropy scanning
//!         --prettyprint        Outputs the JSON in human readable format
//!     -v, --verbose            Sets the level of debugging information
//!     -h, --help               Prints help information
//!     -V, --version            Prints version information
//!
//! OPTIONS:
//!         --authtoken <BEARERTOKEN>    Confluence basic auth bearer token (instead of user & pass)
//!     -o, --outputfile <OUTPUT>        Sets the path to write the scanner results to (stdout by default)
//!         --password <PASSWORD>        Confluence password (crafts basic auth header)
//!         --regex <REGEX>              Sets a custom regex JSON file
//!         --username <USERNAME>        Confluence username (crafts basic auth header)
//!
//! ARGS:
//!     <PAGEID>    The ID (e.g. 1234) of the confluence page you want to scan
//!     <URL>       Base URL of Confluence instance (e.g. https://newrelic.atlassian.net/)

#[macro_use]
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;

use std::io::Read;
use std::collections::{HashSet, BTreeMap};
use log::{self, debug, info, error};
use std::iter::FromIterator;
use clap::ArgMatches;
use regex::bytes::Matches;
use simple_error::SimpleError;
use encoding::DecoderTrap;
use encoding::all::ASCII;
use encoding::types::Encoding;
use rusty_hogs::SecretScanner;
use url::Url;
use hyper::Client;
use hyper::net::HttpsConnector;
use hyper::header::{Authorization, Basic, Headers, Bearer};
use hyper::status::StatusCode;
use rusty_hogs::SecretScannerBuilder;
use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};


/// `serde_json` object that represents a single found secret - finding
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
pub struct ConfluenceFinding {
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub page_id: String,
    pub reason: String,
    pub url: String
}


/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
fn main() {
    let matches = clap_app!(gottingen_hog =>
        (version: "1.1.7")
        (author: "Emily Cain <ecain@newrelic.com>, Scott Cutler")
        (about: "Confluence secret scanner in Rust.")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file")
        (@arg PAGEID: +required "The ID (e.g. 1234) of the confluence page you want to scan")
        (@arg URL: +required +takes_value  "Base URL of Confluence instance (e.g. https://newrelic.atlassian.net/)")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Outputs the JSON in human readable format")
        (@arg USERNAME: --username +takes_value conflicts_with[AUTHTOKEN] "Confluence username (crafts basic auth header)")
        (@arg PASSWORD: --password +takes_value conflicts_with[AUTHTOKEN] "Confluence password (crafts basic auth header)")
        (@arg BEARERTOKEN: --authtoken +takes_value conflicts_with[USERNAME PASSWORD] "Confluence basic auth bearer token (instead of user & pass)")
    )
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => error!( "Error running command: {}", e)
    }
}

/// Main logic contained here. Get the CLI variables, create the appropriate TLS objects,
/// make the TLS calls, and scan the result..
fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    SecretScanner::set_logging(arg_matches.occurrences_of("VERBOSE"));

    // initialize the basic variables and CLI options
    let ssb = SecretScannerBuilder::new().conf_argm(arg_matches);
    let secret_scanner = ssb.build();

    let username = arg_matches
        .value_of("USERNAME");
    let password = arg_matches
        .value_of("PASSWORD");
    let authtoken = arg_matches
        .value_of("BEARERTOKEN");
    let base_url_input = arg_matches
        .value_of("URL")
        .unwrap_or_else(||"https://confluence.atlassian.com")
        .trim_end_matches('/');
    let base_url_as_url = Url::parse(base_url_input).unwrap();
    let page_id = arg_matches
        .value_of("PAGEID")  // TODO validate the format somehow
        .unwrap();

    let base_url = base_url_as_url.as_str();

    // Still inside `async fn main`...
    let client = Client::with_connector(HttpsConnector::new(hyper_rustls::TlsClient::new()));

    // TODO: Support other modes of JIRA authentication
    let mut auth_headers = Headers::new();
    match username {
        // craft auth header using username and password if present
        Some(u) => {
            let atlassianpassword = password.unwrap().to_owned();
            auth_headers.set(
                Authorization(
                    Basic {
                        username: u.to_owned(),
                        password: Some(atlassianpassword)
                    }
                )
            );
        },
        // otherwise use AUTHTOKEN to craft the auth header
        None => {
            auth_headers.set(
                Authorization(
                    Bearer {
                        token: authtoken.unwrap().to_owned()
                    })
            );
        }
    }


    // Build the URL
    let full_url = format!("{}wiki/rest/api/content/{}?expand=body.storage", base_url, page_id);

    let json_results = get_issue_json(client, auth_headers, &full_url);

    let body = json_results.get("body").unwrap().get("storage").unwrap().get("value").unwrap().as_str().unwrap().as_bytes();
    let webui = json_results.get("_links").unwrap().get("webui").unwrap().as_str().unwrap().trim_start_matches('/');
    let web_link = format!("{}wiki/{}", base_url, webui);

    // find secrets in issue body
    let secrets = get_findings(&secret_scanner, page_id, body, &web_link);

    // combine and output the results
    let findings: HashSet<ConfluenceFinding> = HashSet::from_iter(secrets.into_iter());
    info!("Found {} secrets", findings.len());
    match secret_scanner.output_findings(&findings) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with("failed to output findings", SimpleError::new(err.to_string())))
    }
}

/// Uses a hyper::client object to perform a GET on the full_url and return parsed serde JSON data
fn get_issue_json(client: Client, auth_headers: Headers, full_url: &str) -> Map<String, Value> {
    let mut resp = client.get(full_url).headers(auth_headers).send().unwrap();
    debug!("sending request to {}", full_url);
    debug!("Response: {}", resp.status);
    let mut response_body: String = String::new();
    resp.read_to_string(&mut response_body).unwrap();
    if resp.status != StatusCode::Ok {
        panic!("Request to {} failed with code {}: {}", full_url, resp.status, response_body)
    }
    let json_results = serde_json::from_str(&response_body).unwrap();
    debug!("Response JSON: \n{:?}", json_results);
    json_results
}

/// Takes the Confluence finding data (issue_id, description, web_link) and a `SecretScanner`
/// object and produces a list of `ConfluenceFinding` objects. `description` is a &[u8]
fn get_findings(secret_scanner: &SecretScanner, issue_id: &str, description: &[u8], web_link: &str) -> Vec<ConfluenceFinding> {
// Await the response...
// note that get takes &String, or str

    let lines = description.split(|&x| (x as char) == '\n');
    let mut secrets: Vec<ConfluenceFinding> = Vec::new();
    for new_line in lines {
        let matches_map: BTreeMap<&String, Matches> = secret_scanner.matches(new_line);
        for (reason, match_iterator) in matches_map {
            let mut secrets_for_reason: HashSet<String> = HashSet::new();
            for matchobj in match_iterator {
                secrets_for_reason.insert(
                    ASCII
                        .decode(
                            &new_line[matchobj.start()..matchobj.end()],
                            DecoderTrap::Ignore,
                        )
                        .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                );
            }
            if !secrets_for_reason.is_empty() {
                secrets.push(ConfluenceFinding {
                    strings_found: Vec::from_iter(secrets_for_reason.iter().cloned()),
                    page_id: String::from(issue_id),
                    reason: String::from(reason),
                    url: String::from(web_link)
                });
            }
        }
    }
    secrets
}

#[macro_use]
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;

use std::io::Read;
use std::collections::{HashSet, BTreeMap};
use log::{self, debug, error, info};
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
use hyper::header::{Authorization, Basic, Headers};
use rusty_hogs::SecretScannerBuilder;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
pub struct JiraFinding {
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub issue_id: String,
    pub reason: String,
    pub web_link: String,
}


/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
fn main() {
    let matches = clap_app!(gottingen_hog =>
        (version: "1.0.1")
        (author: "Emily Cain <ecain@newrelic.com>")
        (about: "Jira secret scanner in Rust.")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file")
        (@arg JIRAID: +required "The ID (e.g. PROJECT-123) of the Jira issue you want to scan")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Outputs the JSON in human readable format")
        (@arg USERNAME: --username +takes_value +required  "Jira username")
        (@arg PASSWORD: --password +takes_value +required  "Jira password (or API token)")
        (@arg JIRAURL: --url +takes_value)
    )
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => panic!("error: {}", e),
    }
}

fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    SecretScanner::set_logging(arg_matches.occurrences_of("VERBOSE"));

    let ssb = SecretScannerBuilder::new().conf_argm(arg_matches);
    let secret_scanner = ssb.build();

    let jirausername = arg_matches
        .value_of("USERNAME")
        .unwrap();
    let jirapassword = arg_matches
        .value_of("PASSWORD")
        .unwrap();
    let base_url_input = arg_matches
        .value_of("JIRAURL")
        .unwrap_or_else(||"https://jira.atlassian.com");
    let base_url = Url::parse(base_url_input).unwrap();
    let issue_id = arg_matches
        .value_of("JIRAID")  // TODO validate the format somehow
        .unwrap();

    // Still inside `async fn main`...
    let client = Client::with_connector(HttpsConnector::new(hyper_rustls::TlsClient::new()));

    let mut auth_headers = Headers::new();
    auth_headers.set(
        Authorization(
            Basic {
                username: jirausername.to_owned(),
                password: Some(jirapassword.to_owned())
            }
        )
    );

    // Build the URL
    // todo make this work regardless of whether the url argument they pass has a trailing slash
    let full_url = format!("{}rest/api/2/issue/{}", base_url, issue_id);

    let secrets = get_issue_findings(&secret_scanner, base_url, issue_id, client, auth_headers, &full_url);

    let findings: HashSet<JiraFinding> = HashSet::from_iter(secrets.into_iter());
    info!("Found {} secrets", findings.len());
    secret_scanner.output_findings(&findings);

    Ok(())
}

fn get_issue_findings(secret_scanner: &SecretScanner, base_url: Url, issue_id: &str, client: Client, auth_headers: Headers, full_url: &String) -> Vec<JiraFinding> {
// Await the response...
// note that get takes &String, or str
    let mut resp = client.get(full_url).headers(auth_headers).send().unwrap();
    debug!("sending request to {}", full_url);
    debug!("Response: {}", resp.status);
    let mut response_body: String = String::new();
    let response_length = resp.read_to_string(&mut response_body).unwrap();
    debug!("result 1: {}", response_body);
    debug!("result 2: {}", response_length);
    let json_results = rusty_hogs::SecretScannerBuilder::build_json_from_str(&response_body).unwrap();
    debug!("{}", json_results.get("expand").unwrap());
    debug!("{:?}", json_results);
    let description = json_results
        .get("fields").unwrap()
        .get("description").unwrap()
        .as_str().unwrap()
        .as_bytes();
    let lines = description.split(|&x| (x as char) == '\n');
    let mut secrets: Vec<JiraFinding> = Vec::new();
    let web_link = format!("{}browse/{}", base_url, issue_id);
    for new_line in lines {
        let matches_map: BTreeMap<&String, Matches> = secret_scanner.matches(new_line);
        for (reason, match_iterator) in matches_map {
            let mut secrets_for_reason: Vec<String> = Vec::new();
            for matchobj in match_iterator {
                secrets_for_reason.push(
                    ASCII
                        .decode(
                            &new_line[matchobj.start()..matchobj.end()],
                            DecoderTrap::Ignore,
                        )
                        .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap()),
                );
            }
            if secrets_for_reason.len() > 0 {
                secrets.push(JiraFinding {
                    strings_found: secrets_for_reason,
                    issue_id: String::from(issue_id),
                    reason: String::from(reason),
                    web_link: web_link.clone(),
                });
            }
        }
    }
    secrets
}

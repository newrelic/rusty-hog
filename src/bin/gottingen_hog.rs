#[macro_use]
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;

use std::io::Read;
use clap::ArgMatches;
use simple_error::SimpleError;
use rusty_hogs::SecretScanner;
use url::Url;
use hyper::Client;
use hyper::net::HttpsConnector;
use hyper::header::{Authorization, Basic, Headers};

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

    // Await the response...
    // note that get takes &String, or str
    let mut resp = client.get(&full_url).headers(auth_headers).send().unwrap();

    println!("sending request to {}", full_url);
    println!("Response: {}", resp.status);

    let mut response_body :String = String::new();
    let response_length = resp.read_to_string(&mut response_body).unwrap();

    println!("result 1: {}", response_body);
    println!("result 2: {}", response_length);

    let json_results = rusty_hogs::SecretScannerBuilder::build_json_from_str(&response_body).unwrap();

    println!("{}", json_results.get("expand").unwrap());
    println!("{:?}", json_results);

    Ok(())
}

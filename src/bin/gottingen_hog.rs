#[macro_use]
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;

use clap::ArgMatches;
use simple_error::SimpleError;
use rusty_hogs::SecretScanner;
use url::Url;
use hyper::Client;
use hyper::net::HttpsConnector;

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

    // Still inside `async fn main`...
    let client = Client::with_connector(HttpsConnector::new(hyper_rustls::TlsClient::new()));

    // Await the response...
    let resp = client.get(base_url_input).send().unwrap();

    println!("Response: {}", resp.status);

    Ok(())
}

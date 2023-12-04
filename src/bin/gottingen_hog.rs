//! Jira secret scanner in Rust.
//!
//! USAGE:
//!     gottingen_hog [FLAGS] [OPTIONS] <JIRAID> --password <PASSWORD> --username <USERNAME>
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
//!         --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
//!         --url <JIRAURL>
//!     -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
//!         --password <PASSWORD>    Jira password (or API token)
//!         --regex <REGEX>          Sets a custom regex JSON file
//!         --username <USERNAME>    Jira username
//!
//! ARGS:
//!     <JIRAID>    The ID (e.g. PROJECT-123) of the Jira issue you want to scan

extern crate clap;
extern crate hyper;
extern crate hyper_rustls;

use base64::{Engine as _, engine::general_purpose as Base64Engine};
use clap::{Arg, ArgAction, ArgMatches, Command};
use encoding::all::ASCII;
use encoding::types::Encoding;
use encoding::DecoderTrap;
use hyper::body;
use hyper::header::AUTHORIZATION;
use hyper::http::Request;
use hyper::http::StatusCode;
use hyper::{client, Body, Client};
use log::{self, debug, error, info};
use rusty_hog_scanner::SecretScannerBuilder;
use rusty_hog_scanner::{RustyHogMatch, SecretScanner};
use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};
use simple_error::SimpleError;
use std::collections::{BTreeMap, HashSet};
use url::Url;

/// `serde_json` object that represents a single found secret - finding
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
pub struct JiraFinding {
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub issue_id: String,
    pub reason: String,
    pub url: String,
    pub location: String,
}

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
#[tokio::main]
async fn main() {
    let matches: ArgMatches = Command::new("gottingen_hog")
        .version("1.0.11")
        .author("Emily Cain <ecain@newrelic.com>")
        .about("Jira secret scanner in Rust.")
        .arg(Arg::new("REGEX").long("regex").action(ArgAction::Set).help("Sets a custom regex JSON file"))
        .arg(Arg::new("JIRAID").required(true).action(ArgAction::Set).help("The ID (e.g. PROJECT-123) of the Jira issue you want to scan"))
        .arg(Arg::new("VERBOSE").short('v').long("verbose").action(ArgAction::Count).help("Sets the level of debugging information"))
        .arg(Arg::new("ENTROPY").long("entropy").action(ArgAction::SetTrue).help("Enables entropy scanning"))
        .arg(Arg::new("DEFAULT_ENTROPY_THRESHOLD").long("default_entropy_threshold").action(ArgAction::Set).default_value("0.6").help("Default entropy threshold (0.6 by default)"))
        .arg(Arg::new("CASE").long("caseinsensitive").action(ArgAction::SetTrue).help("Sets the case insensitive flag for all regexes"))
        .arg(Arg::new("OUTPUT").short('o').long("outputfile").action(ArgAction::Set).help("Sets the path to write the scanner results to (stdout by default)"))
        .arg(Arg::new("PRETTYPRINT").long("prettyprint").action(ArgAction::SetTrue).help("Outputs the JSON in human readable format"))
        .arg(Arg::new("USERNAME").long("username").action(ArgAction::Set).conflicts_with("BEARERTOKEN").help("Jira username (crafts basic auth header)"))
        .arg(Arg::new("PASSWORD").long("password").action(ArgAction::Set).conflicts_with("BEARERTOKEN").help("Jira password (crafts basic auth header)"))
        .arg(Arg::new("BEARERTOKEN").long("authtoken").action(ArgAction::Set).conflicts_with_all(["USERNAME","PASSWORD"]).help("Jira basic auth bearer token (instead of user & pass)"))
        .arg(Arg::new("JIRAURL").long("url").action(ArgAction::Set).help("Base URL of JIRA instance (e.g. https://jira.atlassian.net/)"))
        .arg(Arg::new("ALLOWLIST").short('a').long("allowlist").action(ArgAction::Set).help("Sets a custom allowlist JSON file"))
        .get_matches();
    match run(matches).await {
        Ok(()) => {}
        Err(e) => error!("Error running command: {}", e),
    }
}

/// Main logic contained here. Get the CLI variables, create the appropriate TLS objects,
/// make the TLS calls, and scan the result..
async fn run(arg_matches: ArgMatches) -> Result<(), SimpleError> {
    SecretScanner::set_logging(arg_matches.get_count("VERBOSE").into());

    // initialize the basic variables and CLI options
    let ssb = SecretScannerBuilder::new().conf_argm(&arg_matches);
    let secret_scanner = ssb.build();

    let jirausername = arg_matches.get_one::<String>("USERNAME");
    let jirapassword = arg_matches.get_one::<String>("PASSWORD");
    let jiraauthtoken = arg_matches.get_one::<String>("BEARERTOKEN");
    let base_url_input = arg_matches
        .get_one::<String>("JIRAURL")
        .map(|s| s.as_str())
        .unwrap_or("https://jira.atlassian.com/");
    let base_url_as_url = Url::parse(base_url_input).unwrap();
    let issue_id = arg_matches
        .get_one::<String>("JIRAID") // TODO validate the format somehow
        .unwrap();

    let base_url = base_url_as_url.as_str();

    // Still inside `async fn main`...
    let https = hyper_rustls::HttpsConnector::with_native_roots();
    let hyper_client: client::Client<_, hyper::Body> = client::Client::builder().build(https);

    // TODO: Support other modes of JIRA authentication
    let auth_string = match jirausername {
        // craft auth header using username and password if present
        Some(u) => {
            format!(
                "Basic {}",
                Base64Engine::STANDARD_NO_PAD.encode(format!("{}:{}", u, jirapassword.unwrap()))
            )
        }
        // otherwise use AUTHTOKEN to craft the auth header
        None => {
            format!("Bearer {}", jiraauthtoken.unwrap())
        }
    };

    // Build the URL
    // todo make this work regardless of whether the url argument they pass has a trailing slash
    let full_url = format!("{}rest/api/2/issue/{}", base_url, issue_id);

    let json_results = get_issue_json(hyper_client, auth_string, &full_url).await;

    let fields = json_results.get("fields").unwrap();

    let description = match fields.get("description") {
        Some(d) => match d.as_str() {
            Some(e) => e.as_bytes(),
            None => {
                info!("The JIRA ticket description was set to null!");
                b""
            }
        },
        None => {
            info!("The JIRA ticket description was not present!");
            b""
        }
    };

    // find secrets in issue body
    let mut secrets = get_findings(
        &secret_scanner,
        base_url,
        issue_id,
        description,
        String::from("Issue Description"),
    );

    let all_comments = json_results
        .get("fields")
        .unwrap()
        .get("comment")
        .unwrap()
        .get("comments")
        .unwrap()
        .as_array()
        .unwrap();

    // find secrets in each comment
    for comment in all_comments {
        let location = format!(
            "comment by {} on {}",
            comment.get("author").unwrap().get("displayName").unwrap(),
            comment.get("created").unwrap()
        );
        let comment_body = comment.get("body").unwrap().as_str().unwrap().as_bytes();
        let comment_findings =
            get_findings(&secret_scanner, base_url, issue_id, comment_body, location);
        secrets.extend(comment_findings);
    }

    // combine and output the results
    let findings: HashSet<JiraFinding> = secrets.into_iter().collect();
    info!("Found {} secrets", findings.len());
    match secret_scanner.output_findings(&findings) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with(
            "failed to output findings",
            SimpleError::new(err.to_string()),
        )),
    }
}

/// Uses a hyper::client object to perform a GET on the full_url and return parsed serde JSON data
async fn get_issue_json<'a, C>(
    hyper_client: Client<C>,
    auth_headers: String,
    full_url: &str,
) -> Map<String, Value>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
{
    debug!("auth header: {}", auth_headers);
    let req_builder = Request::builder()
        .header(AUTHORIZATION, auth_headers)
        .uri(full_url);
    let r = req_builder.body(Body::empty()).unwrap();
    let resp = hyper_client.request(r).await.unwrap();
    debug!("sending request to {}", full_url);
    let status = resp.status().clone();
    debug!("Response: {:?}", status);
    let data = body::to_bytes(resp.into_body()).await.unwrap();
    let data_vec: Vec<u8> = data.to_vec();
    let response_body: String = String::from(std::str::from_utf8(&data_vec).unwrap());
    if status != StatusCode::OK {
        panic!(
            "Request to {} failed with code {:?}: {}",
            full_url, status, response_body
        )
    }
    let json_results = serde_json::from_str(&response_body).unwrap();
    debug!("Response JSON: \n{:?}", json_results);
    json_results
}

/// Takes the JIRA finding data (base_url, issue_id, description, location) and a `SecretScanner`
/// object and produces a list of `JiraFinding` objects. Because `description` is a &[u8] the
/// function can be reused for any part of the ticket (description, comments, etc.)
fn get_findings(
    secret_scanner: &SecretScanner,
    base_url: &str,
    issue_id: &str,
    description: &[u8],
    location: String,
) -> Vec<JiraFinding> {
    // Await the response...
    // note that get takes &String, or str

    let lines = description.split(|&x| (x as char) == '\n');
    let mut secrets: Vec<JiraFinding> = Vec::new();
    let web_link = format!("{}browse/{}", base_url, issue_id);
    for new_line in lines {
        debug!("{:?}", std::str::from_utf8(new_line));
        let matches_map: BTreeMap<String, Vec<RustyHogMatch>> =
            secret_scanner.matches_entropy(new_line);
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
                secrets.push(JiraFinding {
                    strings_found: secrets_for_reason.iter().cloned().collect(),
                    issue_id: String::from(issue_id),
                    reason,
                    url: web_link.clone(),
                    location: location.clone(),
                });
            }
        }
    }
    secrets
}

//! Slack secret scanner in Rust.
//!
//! USAGE:
//!     slack_hog [FLAGS] [OPTIONS] <CHANNEL_ID> --authtoken <BEARERTOKEN>
//!     slack_hog -h | --help
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
//!         --url <SLACKURL> Base URL of Slack Workspace (e.g. https://[WORKSPACE NAME].slack.com)
//!     -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
//!         --authtoken <BEARERTOKEN>    Slack API Token (or API token)
//!         --regex <REGEX>          Sets a custom regex JSON file
//!
//! ARGS:
//!     <CHANNEL_ID>    The ID (e.g. C12345) of the Slack channel you want to scan

#[macro_use]
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;

use clap::ArgMatches;
use encoding::all::ASCII;
use encoding::types::Encoding;
use encoding::DecoderTrap;
use hyper::body;
use hyper::header::AUTHORIZATION;
use hyper::http::Request;
use hyper::http::StatusCode;
use hyper::{client, Body, Client, Method};
use log::{self, debug, error, info};
use rusty_hogs::SecretScannerBuilder;
use rusty_hogs::{RustyHogMatch, SecretScanner};
use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};
use simple_error::SimpleError;
use std::collections::{BTreeMap, HashSet};
use url::Url;

/// SlackFinding is `serde_json` object that represents a single found secret
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
pub struct SlackFinding {
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub channel_id: String,
    pub reason: String,
    pub url: String,
    pub ts: String,
    pub location: String,
}

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
#[tokio::main]
async fn main() {
    let matches: ArgMatches = clap_app!(slack_hog =>
        (version: "0.0.1")
        (author: "Joao Henrique Machado Silva <joaoh82@gmail.com>")
        (about: "Slack secret scanner in Rust.")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file")
        (@arg CHANNELID: +required "The ID (e.g. C12345) of the Slack channel you want to scan")
        (@arg VERBOSE: -v --verbose ... "Sets the level of debugging information")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg DEFAULT_ENTROPY_THRESHOLD: --default_entropy_threshold +takes_value "Default entropy threshold (0.6 by default)")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Outputs the JSON in human readable format")
        (@arg BEARERTOKEN: --authtoken +takes_value +required  "Slack basic auth bearer token")
        (@arg SLACKURL: --url +takes_value +required  "Base URL of Slack Workspace (e.g. https://[WORKSPACE NAME].slack.com)")
        (@arg ALLOWLIST: -a --allowlist +takes_value "Sets a custom allowlist JSON file")
    )
        .get_matches();
    match run(matches).await {
        Ok(()) => {}
        Err(e) => error!("Error running command: {}", e),
    }
}

/// Main logic contained here. Get the CLI variables, create the appropriate TLS objects,
/// make the TLS calls, and scan the result..
async fn run<'b>(arg_matches: ArgMatches<'b>) -> Result<(), SimpleError> {
    SecretScanner::set_logging(arg_matches.occurrences_of("VERBOSE"));

    // initialize the basic variables and CLI options
    let ssb = SecretScannerBuilder::new().conf_argm(&arg_matches);
    let secret_scanner = ssb.build();

    // Reading the Slack API token from the command line
    let slackauthtoken = arg_matches.value_of("BEARERTOKEN");
    // Reading Slack Channel ID from the command line
    let channel_id = arg_matches
        .value_of("CHANNELID") // TODO validate the format somehow
        .unwrap();
    // Reading the Slack URL from the command line
    let base_url_input = arg_matches
        .value_of("SLACKURL")
        .unwrap();
    // Parse an absolute URL from a string.
    let base_url_as_url = Url::parse(base_url_input).unwrap();
    let base_url = base_url_as_url.as_str();

    // Still inside `async fn main`...
    let https = hyper_rustls::HttpsConnector::with_native_roots();
    let hyper_client: client::Client<_, hyper::Body> = client::Client::builder().build(https);

    // Construction Authentication header
    let auth_string = format!("Bearer {}", slackauthtoken.unwrap());

    // Building URL to request conversation history for the channel
    let full_url = format!("{}/api/conversations.history?channel={}", base_url, channel_id);

    // Retrieving the history of the channel
    let json_results = get_channel_history_json(hyper_client, auth_string, &full_url).await;

    // Parsing the messages as an array
    let messages = json_results
        .get("messages")
        .unwrap()
        .as_array()
        .unwrap();

    // Defining and initializing the vector of found secrets
    let mut secrets: Vec<SlackFinding> = Vec::new();

    // find secrets in each message
    for message in messages {
        // ts stands for timestamp
        let ts = message.get("ts").unwrap().as_str().unwrap(); 
        let location = format!(
            "message type {} by {} on {}",
            message.get("type").unwrap(),
            message.get("user").unwrap(),
            message.get("ts").unwrap()
        );
        let message_text = message.get("text").unwrap().as_str().unwrap().as_bytes();

        let message_findings = get_findings(&secret_scanner, base_url, channel_id, ts, message_text, location);
        secrets.extend(message_findings);
    }

    // combine and output the results
    let findings: HashSet<SlackFinding> = secrets.into_iter().collect();
    info!("Found {} secrets", findings.len());
    match secret_scanner.output_findings(&findings) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with(
            "failed to output findings",
            SimpleError::new(err.to_string()),
        )),
    }
}

// TODO: Deal with Slack API Pagination in case of too many messages
// TODO: Deal with Slack API messages per date range
// TODO: move this to a separate file
/// get_channel_history_json uses a hyper::client object to perform a POST on the full_url and return parsed serde JSON data
async fn get_channel_history_json<'a, C>(
    hyper_client: Client<C>,
    auth_headers: String,
    full_url: &str,
) -> Map<String, Value>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
{
    debug!("auth header: {}", auth_headers);

    let req_builder = Request::builder()
        .method(Method::POST)
        .header(AUTHORIZATION, auth_headers)
        .header("content-type", "application/json")
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

/// Takes the Slack finding data (base_url, channel_id, ts(timestamp) description, location) and a `SecretScanner`
/// object and produces a list of `SlackFinding` objects. Reminding `description` is a &[u8].
fn get_findings(
    secret_scanner: &SecretScanner,
    base_url: &str,
    channel_id: &str,
    ts: &str,
    description: &[u8],
    location: String,
) -> Vec<SlackFinding> {

    let lines = description.split(|&x| (x as char) == '\n');
    let mut secrets: Vec<SlackFinding> = Vec::new();

    // Building web links for Slack messages
    // https://<WORKSPACE>.slack.com/archives/<CHANNEL_ID/<MESSAGE TIMESTAMP> 
    let msg_id = str::replace(ts, ".", "");
    let web_link = format!("{}/archives/{}/p{}", base_url, channel_id, msg_id);

    // Iterate over each line of the message
    for new_line in lines {
        debug!("{:?}", std::str::from_utf8(new_line));
        // Builds a BTreeMap of the findings
        let matches_map: BTreeMap<String, Vec<RustyHogMatch>> = secret_scanner.matches_entropy(new_line);

        // Iterate over the findings and add them to the list of findings to return
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
                secrets.push(SlackFinding {
                    strings_found: secrets_for_reason.iter().cloned().collect(),
                    channel_id: String::from(channel_id),
                    reason,
                    url: web_link.clone(),
                    ts: String::from(ts),
                    location: location.clone(),
                });
            }
        }
    }
    secrets
}

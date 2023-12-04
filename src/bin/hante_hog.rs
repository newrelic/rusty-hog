//! Slack secret scanner in Rust.
//!
//! USAGE:
//!     hante_hog [FLAGS] [OPTIONS] --authtoken <BEARERTOKEN> --channelid <CHANNELID> --url <SLACKURL>
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
//!     -a, --allowlist <ALLOWLIST>                                    Sets a custom allowlist JSON file
//!         --authtoken <BEARERTOKEN>                                  Slack basic auth bearer token
//!         --channelid <CHANNELID>
//!             The ID (e.g. C12345) of the Slack channel you want to scan
//!
//!         --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
//!         --latest <LATEST>                                          End of time range of messages to include in search
//!         --oldest <OLDEST>                                          Start of time range of messages to include in search
//!     -o, --outputfile <OUTPUT>
//!             Sets the path to write the scanner results to (stdout by default)
//!
//!         --regex <REGEX>                                            Sets a custom regex JSON file
//!         --url <SLACKURL>
//!             Base URL of Slack Workspace (e.g. https://[WORKSPACE NAME].slack.com)

extern crate clap;
extern crate hyper;
extern crate hyper_rustls;

use clap::{Arg, ArgAction, ArgMatches, Command};
use encoding::all::ASCII;
use encoding::types::Encoding;
use encoding::DecoderTrap;
use hyper::body;
use hyper::header::AUTHORIZATION;
use hyper::http::Request;
use hyper::http::StatusCode;
use hyper::{client, Body, Client, Method};
use log::{self, debug, error, info};
use rusty_hog_scanner::SecretScannerBuilder;
use rusty_hog_scanner::{RustyHogMatch, SecretScanner};
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
    let matches: ArgMatches = Command::new("hante_hog")
        .version("1.0.11")
        .author("Joao Henrique Machado Silva <joaoh82@gmail.com>")
        .about("Slack secret scanner in Rust.")
        .arg(Arg::new("REGEX").long("regex").action(ArgAction::Set).help("Sets a custom regex JSON file"))
        .arg(Arg::new("CHANNELID").long("channelid").required(true).action(ArgAction::Set).help("The ID (e.g. C12345) of the Slack channel you want to scan"))
        .arg(Arg::new("VERBOSE").short('v').long("verbose").action(ArgAction::Count).help("Sets the level of debugging information"))
        .arg(Arg::new("ENTROPY").long("entropy").action(ArgAction::SetTrue).help("Enables entropy scanning"))
        .arg(Arg::new("DEFAULT_ENTROPY_THRESHOLD").long("default_entropy_threshold").action(ArgAction::Set).default_value("0.6").help("Default entropy threshold (0.6 by default)"))
        .arg(Arg::new("CASE").long("caseinsensitive").action(ArgAction::SetTrue).help("Sets the case insensitive flag for all regexes"))
        .arg(Arg::new("OUTPUT").short('o').long("outputfile").action(ArgAction::Set).help("Sets the path to write the scanner results to (stdout by default)"))
        .arg(Arg::new("PRETTYPRINT").long("prettyprint").action(ArgAction::SetTrue).help("Outputs the JSON in human readable format"))
        .arg(Arg::new("BEARERTOKEN").long("authtoken").required(true).action(ArgAction::Set).help("Slack basic auth bearer token"))
        .arg(Arg::new("SLACKURL").long("url").required(true).action(ArgAction::Set).help("Base URL of Slack Workspace (e.g. https://[WORKSPACE NAME].slack.com)"))
        .arg(Arg::new("ALLOWLIST").short('a').long("allowlist").action(ArgAction::Set).help("Sets a custom allowlist JSON file"))
        .arg(Arg::new("LATEST").long("latest").action(ArgAction::Set).help("End of time range of messages to include in search"))
        .arg(Arg::new("OLDEST").long("oldest").action(ArgAction::Set).help("Start of time range of messages to include in search"))
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

    // Reading the Slack API token from the command line
    let slackauthtoken = arg_matches.get_one::<String>("BEARERTOKEN").map(|s| s.as_str());
    // Reading Slack Channel ID from the command line
    let channel_id = arg_matches
        .get_one::<String>("CHANNELID") // TODO validate the format somehow
        .map(|s| s.as_str())
        .unwrap();
    // Reading the Slack URL from the command line
    let base_url_input = arg_matches
        .get_one::<String>("SLACKURL")
        .map(|s| s.as_str())
        .unwrap();
    // Parse an absolute URL from a string.
    let base_url_as_url = Url::parse(base_url_input).unwrap();
    let base_url = base_url_as_url.as_str();

    // Reading the latest timestamp from the command line
    let latest_input = arg_matches
        .get_one::<String>("LATEST")
        .map(|s| s.as_str());

    // Reading the latest timestamp from the command line
    let oldest_input = arg_matches
        .get_one::<String>("OLDEST")
        .map(|s| s.as_str());

    // Still inside `async fn main`...
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_all_versions()
        .build();
    let hyper_client: client::Client<_, hyper::Body> = client::Client::builder().build(https);

    // Construction Authentication header
    let auth_string = format!("Bearer {}", slackauthtoken.unwrap());

    // Building URL to request conversation history for the channel
    // TODO: Construct the URL using a URL library to avoid weird input issues?
    let full_url = format!("{}/api/conversations.history?channel={}", base_url, channel_id);

    // Retrieving the history of the channel
    let json_results_array = get_channel_history_json(hyper_client, auth_string, &full_url, latest_input, oldest_input).await;
    // WARNING: This method requires storing ALL the slack channel history JSON in memory at once
    // TODO: Re-write these methods to scan each JSON API request - to conserve memory usage

    // Defining and initializing the vector of found secrets
    let mut secrets: Vec<SlackFinding> = Vec::new();

    for json_results in json_results_array.iter() {
        // Parsing the messages as an array
        let messages = json_results
            .get("messages")
            .unwrap()
            .as_array()
            .unwrap();

        // find secrets in each message
        for message in messages {
            // ts stands for timestamp
            let ts = message.get("ts").unwrap().as_str().unwrap();
            let location = format!(
                "message type {} by {} on {}",
                message.get("type").unwrap(),
                message.get("user").unwrap_or(&Value::String("<UNKNOWN>".to_string())),
                message.get("ts").unwrap()
            );
            let message_text = message.get("text").unwrap().as_str().unwrap().as_bytes();

            let message_findings = get_findings(&secret_scanner, base_url, channel_id, ts, message_text, location);
            secrets.extend(message_findings);
        }
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


// TODO: move this to a separate file
/// get_channel_history_json uses a hyper::client object to perform a POST on the full_url and return parsed serde JSON data
async fn get_channel_history_json<'a, C>(
    hyper_client: Client<C>,
    auth_headers: String,
    full_url: &str,
    latest: Option<&str>,
    oldest: Option<&str>,
) -> Vec<Map<String, Value>>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
{
    debug!("auth header: {}", auth_headers);
    let mut full_url_mod: String = String::from(full_url);

    if latest.is_some() {
        full_url_mod += format!("&latest={}", latest.unwrap()).as_str();
    }

    if oldest.is_some() {
        full_url_mod += format!("&oldest={}", oldest.unwrap()).as_str();
    }

    let mut has_more = true;
    let mut output: Vec<Map<String, Value>> = Vec::new();
    let mut cursor: Option<String> = None;

    while has_more {
        if cursor.is_some() {
            debug!("Adding a cursor to the URL {}", cursor.as_ref().unwrap());
            full_url_mod += format!("&cursor={}", cursor.as_ref().unwrap()).as_str();
        }

        let req_builder = Request::builder()
            .method(Method::POST)
            .header(AUTHORIZATION, auth_headers.clone())
            .header("content-type", "application/json")
            .uri(full_url_mod.clone());

        let r = req_builder.body(Body::empty()).unwrap();
        let resp = hyper_client.request(r).await.unwrap();

        debug!("sending request to {}", full_url_mod.clone());

        let status = resp.status().clone();
        debug!("Response: {:?}", status);

        let data = body::to_bytes(resp.into_body()).await.unwrap();
        let data_vec: Vec<u8> = data.to_vec();
        let response_body: String = String::from(std::str::from_utf8(&data_vec).unwrap());
        if status != StatusCode::OK {
            panic!(
                "Request to {} failed with code {:?}: {}",
                full_url_mod.clone(), status, response_body
            )
        }

        let json_results: Map<String, Value> = serde_json::from_str(&response_body).unwrap();
        debug!("Response JSON (data): \n{:?}", json_results);
        let ok: bool = json_results.get("ok").unwrap().as_bool().unwrap();
        if !ok {
            panic!(
                "Request to {} failed with error {:?}: {}",
                full_url_mod.clone(), json_results["error"], response_body
            )
        }
        has_more = json_results.get("has_more").unwrap().as_bool().unwrap();
        if has_more { // TODO: Cleanup weird borrowing issues?
            let rm = json_results.get("response_metadata").unwrap().as_object().unwrap().clone();
            cursor = Some(String::from(rm.get("next_cursor").unwrap().as_str().unwrap()));
        }
        output.push(json_results);

    }
    output
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

//! Slack secret scanner in Rust.
//!
//! USAGE:
//!     slack_hog [FLAGS] [OPTIONS] <CHANNEL_ID> --token <TOKEN>
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
//!     -o, --outputfile <OUTPUT>    Sets the path to write the scanner results to (stdout by default)
//!         --regex <REGEX>          Sets a custom regex JSON file
//!
//! ARGS:
//!     <CHANNEL_ID>    The ID (e.g. C026TAJ77A8) of the slack channel you want to scan
//!     <TOKEN>         slack API token

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
use hyper::{client, Body, Client};
use log::{self, debug, error, info, trace};
use rusty_hogs::SecretScannerBuilder;
use rusty_hogs::{RustyHogMatch, SecretScanner};
use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};
use simple_error::SimpleError;
use std::collections::{BTreeMap, HashSet};

/// `serde_json` object that represents a single found secret - finding
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
pub struct SlackFinding {
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub channel_id: String,
    pub reason: String,
    pub url: String,
}

/*
   Slack response models
*/

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackChannelConversation {
    pub ok: bool,
    pub messages: Vec<Message>,
    #[serde(rename = "has_more")]
    pub has_more: bool,
    #[serde(rename = "pin_count")]
    pub pin_count: i64,
    #[serde(rename = "channel_actions_ts")]
    pub channel_actions_ts: ::serde_json::Value,
    #[serde(rename = "channel_actions_count")]
    pub channel_actions_count: i64,
    #[serde(rename = "response_metadata")]
    pub response_metadata: Option<ResponseMetadata>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    #[serde(rename = "client_msg_id")]
    pub client_msg_id: Option<String>,
    #[serde(rename = "type")]
    pub type_field: String,
    pub text: String,
    pub user: String,
    pub ts: String,
    pub team: Option<String>,
    #[serde(default)]
    pub blocks: Vec<Block>,
    pub subtype: Option<String>,
    pub inviter: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "block_id")]
    pub block_id: String,
    pub elements: Vec<Element>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Element {
    #[serde(rename = "type")]
    pub type_field: String,
    pub elements: Vec<Element2>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Element2 {
    #[serde(rename = "type")]
    pub type_field: String,
    pub text: Option<String>,
    pub name: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMetadata {
    #[serde(rename = "next_cursor")]
    pub next_cursor: String,
}

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
#[tokio::main]
async fn main() {
    let matches: ArgMatches = clap_app!(slack_hog =>
        (version: "0.0.1")
        (author: "Ron Zigelman")
        (about: "Slack conversation history secret scanner in Rust.")
        (@arg CHANNEL_ID: +required "The ID (e.g. C026TAJ77A8) of the slack channel you want to scan")
        (@arg TOKEN: --token +required +takes_value "slack auth bearer token")
        (@arg VERBOSE: -v --verbose +takes_value ... "Sets the level of debugging information")
        (@arg REGEX: --regex +takes_value "Sets a custom regex JSON file")
        (@arg ENTROPY: --entropy ... "Enables entropy scanning")
        (@arg DEFAULT_ENTROPY_THRESHOLD: --default_entropy_threshold +takes_value "Default entropy threshold (0.6 by default)")
        (@arg CASE: --caseinsensitive "Sets the case insensitive flag for all regexes")
        (@arg OUTPUT: -o --outputfile +takes_value "Sets the path to write the scanner results to (stdout by default)")
        (@arg PRETTYPRINT: --prettyprint "Outputs the JSON in human readable format")
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
    // set logging
    set_logger(&arg_matches);

    // initialize the basic variables and CLI options
    let ssb = SecretScannerBuilder::new().conf_argm(&arg_matches);
    let secret_scanner = ssb.build();

    let auth_token = format!("Bearer {}", arg_matches.value_of("TOKEN").unwrap());
    let channel_id = arg_matches
        .value_of("CHANNEL_ID") // TODO validate the format somehow
        .unwrap();

    let https = hyper_rustls::HttpsConnector::with_native_roots();
    let hyper_client: client::Client<_, hyper::Body> = client::Client::builder().build(https);

    let mut read_more = true;
    let mut next_cursor: Option<String> = None;
    while read_more {
        let full_url = build_full_url(channel_id, next_cursor);
        match get_conversations_history_json(&hyper_client, &auth_token, &full_url).await {
            Ok(results) => {
                read_more = results.has_more;
                next_cursor = match &results.response_metadata {
                    Some(r) if read_more => Some(r.next_cursor.clone()),
                    _ => None,
                };

                // find secrets in messages array
                let secrets = get_findings(&secret_scanner, channel_id, &results);

                // combine and output the results
                let findings: HashSet<SlackFinding> = secrets.into_iter().collect();
                if findings.is_empty() {
                    debug!("Did not found secrets");
                } else {
                    info!("Found {} secrets", findings.len());
                }

                if secret_scanner.output_findings(&findings).is_err() {
                    // On error - break from the loop and the function
                    return Err(SimpleError::new("failed to output findings"));
                }
            }
            Err(error) => {
                error!(
                    "Error while trying to retrieve channel history. error details: {}",
                    error
                );
                break;
            }
        }
    }
    Ok(())
}

fn set_logger(arg_matches: &ArgMatches) -> () {
    SecretScanner::set_logging(
        arg_matches
            .value_of("VERBOSE")
            .unwrap_or("1")
            .parse::<u64>()
            .unwrap(),
    );
}

/*
    Build the full url with or without paging mechanism
    based on the has_more and next_cursor arguments

    Example:
    First page up to 1 row in the result
    https://slack.com/api/conversations.history?channel=C026TAJ77A8

    Seconds page with the next cursor
    https://slack.com/api/conversations.history?channel=C026TAJ77A8&cursor=bmV4dF90czoxNjI1MDMxMTk3MDAwNDAw
*/
fn build_full_url(channel_id: &str, next_cursor: Option<String>) -> String {
    let base_url_input = "https://slack.com/api/conversations.history?channel=";
    if let Some(next_cursor) = next_cursor {
        format!("{}{}&cursor={}", base_url_input, channel_id, next_cursor)
    } else {
        format!("{}{}", base_url_input, channel_id)
    }
}

/// Uses a hyper::client object to perform a GET on the full_url
/// and return typed struct of the parsed json.
async fn get_conversations_history_json<'a, C>(
    hyper_client: &Client<C>,
    auth_headers: &str,
    full_url: &str,
) -> Result<SlackChannelConversation, SimpleError>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
{
    trace!("auth header: {}", auth_headers);
    let req_builder = Request::builder()
        .header(AUTHORIZATION, auth_headers)
        .uri(full_url);
    let r = req_builder.body(Body::empty()).unwrap();
    let resp = hyper_client.request(r).await.unwrap();
    debug!("sending request to {}", full_url);
    let status = resp.status().clone();
    debug!("Response status: {:?}", status);
    let data = body::to_bytes(resp.into_body()).await.unwrap();
    let data_vec: Vec<u8> = data.to_vec();
    let response_body: String = String::from(std::str::from_utf8(&data_vec).unwrap());
    debug!("response_body: \n{:?}", response_body);
    if status != StatusCode::OK {
        error!(
            "Request to {} failed with code {:?}: {}",
            full_url, status, response_body
        );
        return Err(SimpleError::new(format!("Error status: {}", status)));
    }

    // treat error case before deserialize into typed struct
    // todo find a better way to avoid deserialize twice?
    let json_results: Map<String, Value> = serde_json::from_str(&response_body).unwrap();
    let ok_result = json_results.get("ok").unwrap().as_bool();
    if ok_result.is_none() || !ok_result.unwrap() {
        let error = json_results.get("error").unwrap().as_str().unwrap();
        error!("Response contains error: {}", error);
        return Err(SimpleError::new(format!("Error: {}", error)));
    }
    let typed_result: SlackChannelConversation = serde_json::from_str(&response_body).unwrap();
    Ok(typed_result)
}

/// Takes the Slack finding data (base_url, channel_id, SlackChannelConversation) and a `SecretScanner`
/// object and produces a list of `SlackFinding` objects.
fn get_findings(
    secret_scanner: &SecretScanner,
    channel_id: &str,
    slack_results: &SlackChannelConversation,
) -> Vec<SlackFinding> {
    let mut secrets: Vec<SlackFinding> = Vec::new();
    for message in &slack_results.messages {
        let message_buffer = message.text.as_bytes();
        let matches_map: BTreeMap<String, Vec<RustyHogMatch>> =
            secret_scanner.matches_entropy(message_buffer);
        for (reason, match_iterator) in matches_map {
            let mut secrets_for_reason: HashSet<String> = HashSet::new();
            for matchobj in match_iterator {
                secrets_for_reason.insert(
                    ASCII
                        .decode(
                            &message_buffer[matchobj.start()..matchobj.end()],
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
                    url: get_secret_url(&message.team, &channel_id),
                });
            }
        }
    }
    secrets
}

fn get_secret_url(team: &Option<String>, channel_id: &str) -> String {
    /*
       Todo link to the specific message.
       The share option provide similar link with the message ts value
       converted without the decimal point and prefixed by 'p'
       but it's doesn't work correctly and open redirecting page
    */
    let base_secret_url = "https://app.slack.com/client";
    match team {
        Some(team) => format!("{}/{}/{}", base_secret_url, team, channel_id),
        None => "".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_conversation_paging_result_ok() {
        let json = r#"{
            "ok": true,
            "messages": [
                {
                    "client_msg_id": "ef755449-6868-4256-9f12-1974e9a306f7",
                    "type": "message",
                    "text": ":wave: Hello, team!",
                    "user": "U026ZPTQDUH",
                    "ts": "1625031197.000400",
                    "team": "T0266CMJH1D",
                    "blocks": [
                        {
                            "type": "rich_text",
                            "block_id": "xWhTV",
                            "elements": [
                                {
                                    "type": "rich_text_section",
                                    "elements": [
                                        {
                                            "type": "emoji",
                                            "name": "wave"
                                        },
                                        {
                                            "type": "text",
                                            "text": " Hello, team!"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ],
            "has_more": true,
            "pin_count": 0,
            "channel_actions_ts": null,
            "channel_actions_count": 0,
            "response_metadata": {
                "next_cursor": "bmV4dF90czoxNjI1MDMxMTQyMDAwMjAw"
            }
        }"#;
        let slack_conversation_result =
            serde_json::from_str::<SlackChannelConversation>(json).unwrap();
        assert_eq!(
            slack_conversation_result
                .response_metadata
                .unwrap()
                .next_cursor,
            "bmV4dF90czoxNjI1MDMxMTQyMDAwMjAw"
        );
        assert_eq!(slack_conversation_result.has_more, true);
        assert_eq!(slack_conversation_result.ok, true);
        assert_eq!(
            slack_conversation_result.messages[0].ts,
            "1625031197.000400"
        );
        assert_eq!(
            slack_conversation_result.messages[0].blocks[0].elements[0].elements[1].text,
            Some(" Hello, team!".to_string())
        );
    }

    #[test]
    fn deserialize_long_conversation_result() {
        let json = r#"{"ok":true,"messages":[{"client_msg_id":"545856d9-4dac-49bb-9f43-20ddc8590e51","type":"message","text":"ddddddd","user":"U026ZPTQDUH","ts":"1625077034.000600","team":"T0266CMJH1D","blocks":[{"type":"rich_text","block_id":"3ou","elements":[{"type":"rich_text_section","elements":[{"type":"text","text":"ddddddd"}]}]}]},{"client_msg_id":"dc704064-7645-4350-9142-9a027bf91068","type":"message","text":"ccccccc","user":"U026ZPTQDUH","ts":"1625077032.000400","team":"T0266CMJH1D","blocks":[{"type":"rich_text","block_id":"PfhK7","elements":[{"type":"rich_text_section","elements":[{"type":"text","text":"ccccccc"}]}]}]},{"client_msg_id":"cecb2cd4-7ebf-4d79-8241-ad988dfe9744","type":"message","text":"bbbbbb","user":"U026ZPTQDUH","ts":"1625077029.000200","team":"T0266CMJH1D","blocks":[{"type":"rich_text","block_id":"ClW","elements":[{"type":"rich_text_section","elements":[{"type":"text","text":"bbbbbb"}]}]}]},{"type":"message","subtype":"channel_join","ts":"1625033136.000600","user":"U026TC4CL5A","text":"<@U026TC4CL5A> has joined the channel","inviter":"U026ZPTQDUH"},{"client_msg_id":"ef755449-6868-4256-9f12-1974e9a306f7","type":"message","text":":wave: Hello, team!","user":"U026ZPTQDUH","ts":"1625031197.000400","team":"T0266CMJH1D","blocks":[{"type":"rich_text","block_id":"xWhTV","elements":[{"type":"rich_text_section","elements":[{"type":"emoji","name":"wave"},{"type":"text","text":" Hello, team!"}]}]}]},{"type":"message","subtype":"channel_join","ts":"1625031142.000200","user":"U026ZPTQDUH","text":"<@U026ZPTQDUH> has joined the channel"}],"has_more":false,"pin_count":0,"channel_actions_ts":null,"channel_actions_count":0}"#;

        let slack_conversation_result =
            serde_json::from_str::<SlackChannelConversation>(json).unwrap();

        assert_eq!(slack_conversation_result.has_more, false);
        assert_eq!(slack_conversation_result.ok, true);
        assert_eq!(
            slack_conversation_result.messages[0].ts,
            "1625077034.000600"
        );
        assert_eq!(
            slack_conversation_result.messages[0].blocks[0].elements[0].elements[0].text,
            Some("ddddddd".to_string())
        );
    }
}

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
//!         --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
//!         --authtoken <BEARERTOKEN>    Confluence basic auth bearer token (instead of user & pass)
//!     -o, --outputfile <OUTPUT>        Sets the path to write the scanner results to (stdout by default)
//!         --password <PASSWORD>        Confluence password (crafts basic auth header)
//!         --regex <REGEX>              Sets a custom regex JSON file
//!         --username <USERNAME>        Confluence username (crafts basic auth header)
//!
//! ARGS:
//!     <PAGEID>    The ID (e.g. 1234) of the confluence page you want to scan
//!     <URL>       Base URL of Confluence instance (e.g. https://newrelic.atlassian.net/)
//!                 From https://docs.atlassian.com/ConfluenceServer/rest/7.11.0/ Structure of the REST URIs section
//!                 for details on declaring the base url with or without context
//!                 With context: http://host:port/context/rest/api/resource-name
//!                 Or without context: http://host:port/rest/api/resource-name
//!                 Example with context: http://example.com:8080/confluence/rest/api/space/ds
//!                 Example without context: http://confluence.myhost.com:8095/rest/api/space/ds

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
pub struct ConfluenceFinding {
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub page_id: String,
    pub reason: String,
    pub url: String,
}

/// stores the content of a confluence page including its body and comments
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
pub struct ConfluencePage {
    web_link: String,
    body: String,
    comments: String,
}

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
#[tokio::main]
async fn main() {
    let matches = Command::new("gottingen_hog")
        .version("1.0.11")
        .author("Emily Cain <ecain@newrelic.com>, Scott Cutler")
        .about("Confluence secret scanner in Rust.")
        .arg(Arg::new("REGEX").long("regex").action(ArgAction::Set).help("Sets a custom regex JSON file"))
        .arg(Arg::new("PAGEID").required(true).action(ArgAction::Set).help("The ID (e.g. 1234) of the confluence page you want to scan"))
        .arg(Arg::new("URL").required(true).action(ArgAction::Set).help("Base URL of Confluence instance (e.g. https://newrelic.atlassian.net/)"))
        .arg(Arg::new("VERBOSE").short('v').long("verbose").action(ArgAction::Count).help("Sets the level of debugging information"))
        .arg(Arg::new("ENTROPY").long("entropy").action(ArgAction::Set).help("Enables entropy scanning"))
        .arg(Arg::new("DEFAULT_ENTROPY_THRESHOLD").long("default_entropy_threshold").action(ArgAction::Set).default_value("0.6").help("Default entropy threshold (0.6 by default)"))
        .arg(Arg::new("CASE").long("caseinsensitive").action(ArgAction::SetTrue).help("Sets the case insensitive flag for all regexes"))
        .arg(Arg::new("OUTPUT").short('o').long("outputfile").action(ArgAction::SetTrue).help("Sets the path to write the scanner results to (stdout by default)"))
        .arg(Arg::new("PRETTYPRINT").long("prettyprint").action(ArgAction::SetTrue).help("Outputs the JSON in human readable format"))
        .arg(Arg::new("USERNAME").long("username").action(ArgAction::Set).conflicts_with("BEARERTOKEN").help("Confluence username (crafts basic auth header)"))
        .arg(Arg::new("PASSWORD").long("password").action(ArgAction::Set).conflicts_with("BEARERTOKEN").help("Confluence password (crafts basic auth header)"))
        .arg(Arg::new("BEARERTOKEN").long("authtoken").action(ArgAction::Set).conflicts_with_all(["USERNAME","PASSWORD"]).help("Confluence basic auth bearer token (instead of user & pass)"))
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
        .get_one::<String>("URL")
        .map(|s| s.as_str())
        .unwrap_or("https://confluence.atlassian.com")
        .trim_end_matches('/');
    let base_url_as_url = Url::parse(base_url_input).unwrap();
    let page_id = arg_matches
        .get_one::<String>("PAGEID") // TODO validate the format somehow
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
                base64::encode(format!("{}:{}", u, jirapassword.unwrap()))
            )
        }
        // otherwise use AUTHTOKEN to craft the auth header
        None => {
            format!("Bearer {}", jiraauthtoken.unwrap())
        }
    };

    // fetch the content of confluence page along with the comments
    let page = get_page(hyper_client, auth_string, &base_url, &page_id).await;

    // find secrets in page body and comments
    let mut content = page.body;
    content.push_str(&page.comments);
    let secrets = get_findings(&secret_scanner, page_id, content.as_bytes(), &page.web_link);

    // combine and output the results
    let findings: HashSet<ConfluenceFinding> = secrets.into_iter().collect();
    info!("Found {} secrets", findings.len());
    match secret_scanner.output_findings(&findings) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with(
            "failed to output findings",
            SimpleError::new(err.to_string()),
        )),
    }
}

/// Fetches the body of a confluence page along with the comments
async fn get_page<'a, C>(
    hyper_client: Client<C>,
    auth_headers: String,
    base_url: &str,
    page_id: &str,
) -> ConfluencePage
where
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
{
    let base_url_trimmed = base_url.trim_end_matches('/');
    let page_full_url = format!(
        "{}/rest/api/content/{}?expand=body.storage",
        base_url_trimmed, page_id
    );
    let json_results = get_json(&hyper_client, &auth_headers, &page_full_url).await;
    let body = json_results
        .get("body")
        .unwrap()
        .get("storage")
        .unwrap()
        .get("value")
        .unwrap()
        .as_str()
        .unwrap();
    let webui = json_results
        .get("_links")
        .unwrap()
        .get("webui")
        .unwrap()
        .as_str()
        .unwrap()
        .trim_start_matches('/');
    let web_link = format!("{}/{}", base_url_trimmed, webui);

    let comments_full_url = format!(
        "{}/rest/api/content/{}/child/comment?expand=body.storage",
        base_url_trimmed, page_id
    );
    let json_results = get_json(&hyper_client, &auth_headers, &comments_full_url).await;
    let comments = json_results.get("results").unwrap();
    let mut all_comments: String = String::new();
    if let Value::Array(comments) = comments {
        for comment in comments {
            let comment_body = comment
                .get("body")
                .unwrap()
                .get("storage")
                .unwrap()
                .get("value")
                .unwrap()
                .as_str()
                .unwrap();
            all_comments.push_str(comment_body);
        }
    };

    ConfluencePage {
        web_link,
        body: String::from(body),
        comments: all_comments,
    }
}

/// Uses a hyper::client object to perform a GET on the full_url and return parsed serde JSON data
async fn get_json<'a, C>(
    hyper_client: &Client<C>,
    auth_headers: &String,
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

/// Takes the Confluence finding data (issue_id, description, web_link) and a `SecretScanner`
/// object and produces a list of `ConfluenceFinding` objects. `description` is a &[u8]
fn get_findings(
    secret_scanner: &SecretScanner,
    issue_id: &str,
    content: &[u8],
    web_link: &str,
) -> Vec<ConfluenceFinding> {
    let lines = content.split(|&x| (x as char) == '\n');
    let mut secrets: Vec<ConfluenceFinding> = Vec::new();
    for new_line in lines {
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
                secrets.push(ConfluenceFinding {
                    strings_found: secrets_for_reason.iter().cloned().collect(),
                    page_id: String::from(issue_id),
                    reason,
                    url: String::from(web_link),
                });
            }
        }
    }
    secrets
}

//! An S3 secret scanner designed to be run as a Lambda function
//!  
//! Berkshire Hog is currently designed to be used as a Lambda function. This is the basic data flow:
//!```text
//!    ┌───────────┐              ┌───────┐     ┌────────────────┐     ┌────────────┐
//!    │ S3 bucket │ ┌────────┐   │       │     │ Berkshire Hog  │     │ S3 bucket  │
//!    │  (input) ─┼─┤S3 event├──▶│  SQS  │────▶│    (Lambda)    │────▶│  (output)  │
//!    │           │ └────────┘   │       │     │                │     │            │
//!    └───────────┘              └───────┘     └────────────────┘     └────────────┘
//!```
//!
//!In order to run Berkshire Hog this way, set up the following:
//!1) Configure the input bucket to send an "event" to SQS for each PUSH/PUT event.
//!2) Set up the SQS topic to accept events from S3, including IAM permissions.
//!3) Run Berkshire Hog with IAM access to SQS and S3.

extern crate s3;

use lambda_runtime::{handler_fn, Context, Error};
use log::{self, warn, LevelFilter};
use rusty_hog_scanner::SecretScannerBuilder;
use rusty_hogs::aws_scanning::{S3Finding, S3Scanner};
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use serde_derive::{Deserialize, Serialize};
use simple_error::SimpleError;
use simple_logger::SimpleLogger;
use std::env;
use std::time::SystemTime;

// Each of these structs correspond to parsed JSON objects coming from S3 -> SQS -> Lambda
#[derive(Deserialize, Clone, Debug)]
struct CustomEvent {
    #[serde(rename = "Records")]
    records: Vec<TopRecord>,
}

#[derive(Deserialize, Clone, Debug)]
struct TopRecord {
    body: String,
}

#[derive(Deserialize, Clone, Debug)]
struct Body {
    #[serde(rename = "Records")]
    records: Vec<Record>,
}

#[derive(Deserialize, Clone, Debug)]
struct Record {
    s3: S3,
    #[serde(rename = "awsRegion")]
    aws_region: String,
    #[serde(rename = "eventTime")]
    event_time: String,
}

#[derive(Deserialize, Clone, Debug)]
struct S3 {
    bucket: BucketJson,
    object: S3Object,
}

#[derive(Deserialize, Clone, Debug)]
struct BucketJson {
    name: String,
    #[serde(rename = "ownerIdentity")]
    owner_identity: OwnerIdentity,
    arn: String,
}

#[derive(Deserialize, Clone, Debug)]
struct OwnerIdentity {
    #[serde(rename = "principalId")]
    principal_id: String,
}

#[derive(Deserialize, Clone, Debug)]
struct S3Object {
    key: String,
    size: i32,
    #[serde(rename = "eTag")]
    e_tag: String,
    sequencer: String,
}

// https://robertohuertas.com/2018/12/02/aws-lambda-rust/
#[derive(Serialize, Clone)]
struct CustomOutput {
    #[serde(rename = "isBase64Encoded")]
    is_base64_encoded: bool,
    #[serde(rename = "statusCode")]
    status_code: u16,
    body: Vec<S3Finding>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
struct Finding {
    date: String,
    diff: String,
    #[serde(rename = "stringsFound")]
    strings_found: Vec<String>,
    path: String,
    reason: String,
}

#[tokio::main]
async fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init()
        .unwrap();
    let my_handler = handler_fn(my_handler);
    lambda_runtime::run(my_handler).await.unwrap();
}

async fn my_handler(event: CustomEvent, _: Context) -> Result<CustomOutput, Error> {
    // let event: CustomEvent = serde_json::from_value(e).unwrap();
    warn!("incoming JSON: {:?}", event);
    // Initialize our S3 variables
    let credentials = Credentials::new(None, None, None, None, None).unwrap();
    let output_bucket_name = env::var("OUTPUT_BUCKET_NAME").unwrap();
    let output_bucket_region: Region = env::var("OUTPUT_BUCKET_REGION").unwrap().parse().unwrap();
    let output_bucket_keyprefix = env::var("OUTPUT_BUCKET_KEYPREFIX").unwrap();
    let output_bucket = Bucket::new(
        output_bucket_name.as_ref(),
        output_bucket_region,
        credentials.clone(),
    )
    .unwrap();

    // Main loop - create a list of findings based on each S3 file contained in the json
    let mut findings: Vec<S3Finding> = Vec::new();
    let ss = SecretScannerBuilder::new().build();
    let s3scanner = S3Scanner::new_from_scanner(ss);
    for top_record in event.records {
        let body_obj: Body = serde_json::from_str(top_record.body.as_str()).unwrap(); //yo dawg
        for record in body_obj.records {
            let region_str = record.aws_region;
            let region: Region = region_str.parse().unwrap();
            let bucket_name = record.s3.bucket.name;
            let bucket = Bucket::new(bucket_name.as_ref(), region, credentials.clone()).unwrap();
            let key = record.s3.object.key;
            //            let filesize = record.s3.object.size;
            let f_result: Result<Vec<S3Finding>, SimpleError> =
                s3scanner.scan_s3_file(bucket, key.as_ref());
            match f_result {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => return Err(Error::from(e.as_str())),
            };
        }
    }

    // Cleanup - Write output to S3, return a 200 to lambda
    let output_string: String = serde_json::to_string(&findings).unwrap();
    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dest = format!("{}/{}", output_bucket_keyprefix, epoch);
    output_bucket
        .put_object_with_content_type_blocking(&dest, output_string.as_bytes(), "text/plain")
        .unwrap();
    Ok(CustomOutput {
        is_base64_encoded: false,
        status_code: 200,
        body: findings,
    })
}

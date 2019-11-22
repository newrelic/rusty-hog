#!/bin/bash

if [[ $(uname) != "Darwin" ]]; then
  echo "script currently designed to build for macs and musl"
  exit 1
fi

cargo build --release
if [ $? -ne 0 ]; then
  echo "cargo build returned non-zero exit code"
  exit 1
fi

cross build --release --target x86_64-unknown-linux-musl
if [ $? -ne 0 ]; then
  echo "cross build returned non-zero exit code"
  exit 1
fi

cp target/x86_64-unknown-linux-musl/release/berkshire_hog_lambda bootstrap
zip -j berkshire_lambda.zip bootstrap
mkdir darwin_releases
mkdir musl_releases
cp target/release/*_hog darwin_releases
cp target/x86_64-unknown-linux-musl/release/*_hog musl_releases
zip -r release.zip darwin_releases musl_releases berkshire_lambda.zip
rm -rf darwin_releases musl_releases 
echo "Output build in release.zip"


#!/bin/zsh

cross build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/berkshire_hog_lambda bootstrap
zip -j berkshire_lambda.zip bootstrap

FROM rust:latest
RUN mkdir -p /build
WORKDIR /build
COPY . /build/
RUN cargo build --release

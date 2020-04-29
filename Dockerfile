ARG RUST_VERSION=1.43
FROM rust:${RUST_VERSION} as builder
RUN mkdir -p /build
WORKDIR /build
COPY . /build/
RUN cargo build --release

FROM debian:buster-slim
RUN apt-get update && apt-get install -y openssl openssh-client ca-certificates
COPY --from=builder /build/target/release/*_hog /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/choctaw_hog"]

ARG RUST_VERSION=1.51
FROM rust:${RUST_VERSION} as builder
RUN mkdir -p /build
WORKDIR /build
COPY . /build/
RUN cargo build --release

FROM debian:buster-slim
ARG HOG="choctaw"
ENV HOG_BIN="${HOG}_hog"
RUN apt-get update && apt-get install -y openssl openssh-client ca-certificates
COPY --from=builder /build/target/release/*_hog /usr/local/bin/
ENV PATH=/usr/local/bin:$PATH
COPY ./entrypoint.sh /usr/local/bin
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

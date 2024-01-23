#!/bin/bash

if [[ "$(uname)" != "Darwin" ]]; then
    echo "This script built for macOS";
    exit 1;
fi

[ -z "${OPENSSL_BUILD_VER}" ] && OPENSSL_BUILD_VER="3.0.12"
[ -z "${AMAZON_KERNEL_HEADERS_RPM_URL}" ] && AMAZON_KERNEL_HEADERS_RPM_URL="http://packages.eu-central-1.amazonaws.com/2018.03/updates/adeeb554baf5/x86_64/Packages/kernel-headers-4.14.275-142.503.amzn1.x86_64.rpm"
AMAZON_KERNEL_HEADERS_RPM="${AMAZON_KERNEL_HEADERS_RPM_URL##http*/}"

RUSTYHOGS_BUILD_ROOT="$(pwd)"

# 
# Cross-compile for musl on amd64
# (Done primarily for size reasons)
#
if ! x86_64-linux-musl-gcc --help >/dev/null 2>&1; then
    echo "Couldn't find x86_64-linux-musl-gcc";
    if [ "$(uname)" == "Darwin" -a ! -z "$(which brew)" ]; then
        echo "You may want to run \`brew install FiloSottile/musl-cross/musl-cross\`";
        echo "(and possibly reload your shell)";
        exit 1;
    else
        echo "You may want to set up cross-compilation for musl on x86_64 linux";
    fi
elif ! rpm2cpio >/dev/null 2>&1; then
    echo "You must install rpm2cpio so we can pull linux-headers if we need them"
    exit 1
fi

echo -n "Checking if you're already set up to build against openssl... ";
if ! ( echo "int main(int argc, char *argv[]) { return 0; }" | x86_64-linux-musl-gcc -lcrypto -lssl -x c - -o .comptest >/dev/null 2>&1 ); then
    # We don't have SSL by default
    export OPENSSL_DIR="$(pwd)/build-deps/openssl-${OPENSSL_BUILD_VER}"
    if [ ! -d "${OPENSSL_DIR}" ]; then
        # And we didn't build the directory yet
        echo "no"
        echo "Pulling openssl for build"
        mkdir build-deps
        cd build-deps
        if ! curl -sLO "https://www.openssl.org/source/openssl-${OPENSSL_BUILD_VER}.tar.gz"; then
            echo "Failed to download OpenSSL sources for build"
            exit 1
        fi

        tar xzf openssl-${OPENSSL_BUILD_VER}.tar.gz

        # Do we need linux-headers?
        echo -n "Checking if you're already set up to build (openssl) against x86_64 Linux... ";
        if ! ( echo -e "#include <linux/mman.h>\n\nint main(int argc, char *argv[]) { return 0; }" | x86_64-linux-musl-gcc -x c - -o .comptest >/dev/null 2>&1 ) || [ "$(uname -m)" != "x86_64" ]; then
            # We do need them
            # Either we couldn't compile by default *OR*
            # our machine arch is not x86_64 (which means
            # we might compile with incorrect headers)
            # Therefore, we must pull headers
            echo "no"
            if [ ! -d "linux-headers" ]; then
                # And we need to pull them
                # So pull amazon's kernel-headers package
                # Since the most likely case is deploying to Lambda
                if ! curl -sLO "${AMAZON_KERNEL_HEADERS_RPM_URL}"; then
                    echo "Failed to download Amazon Linux kernel-headers RPM for build"
                    exit 1
                fi
                mkdir -p linux-headers && cd linux-headers
                # Extract them
                rpm2cpio ../${AMAZON_KERNEL_HEADERS_RPM} | cpio -i -d
                # And flatten them back into linux-headers
                mv usr/include/* .
                cd ..
            fi
            # Point CFLAGS here too
            [ -z "${CFLAGS}" ] && export CFLAGS="-I$(pwd)/linux-headers" || export CFLAGS="${CFLAGS} -I$(pwd)/linux-headers"
        else
            if [ ! -d "$(pwd)/linux-headers" ]; then
                # We didn't have to pull linux-headers, so we're using the system's
                # This *should* be fine... might want to check arch
                echo "yes (system)"
            elif ! ( echo -e "#include <linux/mman.h>\n\nint main(int argc, char *argv[]) { return 0; }" | x86_64-linux-musl-gcc -I"$(pwd)/linux-headers" -x c - -o .comptest >/dev/null 2>&1 ); then
                # We already have the directory, but
                # building with that dir didn't work for some reason
                # ... we should get the whole thing rebuilt
                echo "no (headers are there but build failed)"
                echo "We're in a really weird state, you might want to rm -rf build-deps/ and try again"
                exit 1
            else
                # We have the directory and we compiled against it
                # Everything should be ok, make sure we have CFLAGS
                echo "yes (build-deps pre-made)"
                # Make sure CFLAGS get set then as well
                [ -z "${CFLAGS}" ] && export CFLAGS="-I$(pwd)/linux-headers" || export CFLAGS="${CFLAGS} -I$(pwd)/linux-headers"
            fi
        fi

        # Cross-build OpenSSL for musl on linux x86_64
        cd openssl-${OPENSSL_BUILD_VER}
        make clean
        CROSS_COMPILE="x86_64-linux-musl-" ./Configure linux-x86_64
        make
        # Get back to build root
        cd "${RUSTYHOGS_BUILD_ROOT}"
    else
        # We already made the OpenSSL directory
        # and built in it
        if ! ( echo "int main(int argc, char *argv[]) { return 0; }" | x86_64-linux-musl-gcc -x c - -I"${OPENSSL_DIR}/include" -L"${OPENSSL_DIR}" -lssl -lcrypto >/dev/null 2>&1  ); then
            # And it doesn't work? Bad times, we want to rebuild literally everything.
            echo "no"
            echo "Pre-built OpenSSL seems to have failed; rm -rf build-deps and try again"
            exit 1
        else
            # It works, we're all good
            echo "yes (build-deps pre-made)"
        fi
    fi

    # Set up the cross-compile for openssl-sys crate
    # NOTE: CFLAGS and LDFLAGS are updated this way
    # to allow the user to specify their own as well
    export CFLAGS="${CFLAGS} -I${OPENSSL_DIR}/include -L${OPENSSL_DIR}"
    export LDFLAGS="${LDFLAGS} -L${OPENSSL_DIR} -lssl -lcrypto"
    export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR="${OPENSSL_DIR}"
    export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC="${OPENSSL_DIR}"
else
    echo "yes"
fi

# Actually do the cross-compile for the musl releases
if ! TARGET_CC="x86_64-linux-musl-gcc" cargo build --target x86_64-unknown-linux-musl --release --config target.x86_64-unknown-linux-musl.linker='"x86_64-linux-musl-ld"'; then
    echo "Couldn't cross-compile for musl on amd64"
    exit 1
fi

# Prepare berkshire_hog_lambda for lambda
cp target/x86_64-unknown-linux-musl/release/berkshire_hog_lambda bootstrap
zip -j berkshire_lambda.zip bootstrap

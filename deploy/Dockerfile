# SPDX-License-Identifier: Apache-2.0
#
# The pgsnare image: one static binary on a small Alpine base, run by a
# numeric user that is not root.
#
# Build it from the root of the repository:
#
#   docker buildx build --file deploy/Dockerfile .                  the image
#   docker buildx build --file deploy/Dockerfile --target binary \
#       --output type=local,dest=out .                              the binary alone
#
# Both come from the same build stage, so the binary of a release is the
# very file inside the image of that release. The image is built for the
# architecture of the machine that builds it: x86_64 or aarch64.
#
# Every image named here is pinned by tag and by digest. scripts/check-repo.sh
# refuses one that is not.

# --- The build ---------------------------------------------------------------
#
# The Rust image that Dockerfile.dev pins. Keep the two in step, and the
# version in step with rust-toolchain.toml.
FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS build

# musl-tools compiles the C code that pgsnare links against musl: its
# cryptography library and the SQL parser of the rules. The parser needs
# no libclang: the declarations of its C interface are made ahead of time
# (crates/bindgen-prebuilt).
#
# musl-gcc reads the headers of musl and no others. The C code also includes
# headers of the Linux kernel, which do not depend on the C library, so the
# three directories that hold them are linked into the directory of musl.
RUN set -eu; \
    apt-get update; \
    apt-get install --yes --no-install-recommends musl-tools; \
    rm -rf /var/lib/apt/lists/*; \
    gnu="/usr/include/$(uname -m)-linux-gnu"; \
    musl="/usr/include/$(uname -m)-linux-musl"; \
    test -d "$musl"; \
    test -d /usr/include/linux; \
    test -d /usr/include/asm-generic; \
    test -d "$gnu/asm"; \
    ln -s /usr/include/linux "$musl/linux"; \
    ln -s /usr/include/asm-generic "$musl/asm-generic"; \
    ln -s "$gnu/asm" "$musl/asm"

# Limits parallel compilation.
ARG CARGO_BUILD_JOBS

# The C compiler and archiver for the musl targets. Without these the build
# looks for a cross compiler under another name.
ENV CC_x86_64_unknown_linux_musl=musl-gcc \
    AR_x86_64_unknown_linux_musl=ar \
    CC_aarch64_unknown_linux_musl=musl-gcc \
    AR_aarch64_unknown_linux_musl=ar

WORKDIR /build

# The workspace and nothing else: deploy/Dockerfile.dockerignore keeps the
# rest of the repository out of the build. rust-toolchain.toml stays out on
# purpose, so the build uses the toolchain of the image and downloads none.
# The licence of the repository and the script that writes the licence
# notices of the dependencies come in with it, as the image must carry
# both. The script copies the licence files the crates do not carry
# verbatim from the directories deploy/notices/NAME, so those come in
# with it too.
COPY Cargo.toml Cargo.lock LICENSE ./
COPY crates ./crates
COPY scripts/notices.sh scripts/
COPY deploy/notices deploy/notices

# A static binary for the architecture of this machine, with the default
# features, the SQL rules among them, and exactly the dependencies of
# Cargo.lock. The build fails unless the result asks for no interpreter and
# no shared library.
#
# It also fails when protoc is on the PATH: the build script of the SQL
# parser would then generate its Rust types again and overwrite the ones
# that came with the crate, which the rules were written and tested against.
RUN set -eu; \
    if command -v protoc >/dev/null; then \
        echo "the build stage must not contain protoc" >&2; exit 1; \
    fi; \
    case "$(uname -m)" in \
        x86_64) target=x86_64-unknown-linux-musl ;; \
        aarch64) target=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    cargo build --release --locked --package pgsnare --bin pgsnare --target "$target"; \
    install -D --mode 0555 "target/$target/release/pgsnare" /out/pgsnare; \
    scripts/notices.sh /out/notices; \
    install --mode 0644 /out/notices /out/THIRD-PARTY-NOTICES; \
    install --mode 0644 LICENSE /out/LICENSE; \
    if readelf --program-headers --wide /out/pgsnare | grep -q 'INTERP'; then \
        echo "the binary asks for an interpreter" >&2; exit 1; \
    fi; \
    if readelf --dynamic --wide /out/pgsnare | grep -q 'NEEDED'; then \
        echo "the binary asks for a shared library" >&2; exit 1; \
    fi; \
    /out/pgsnare --version

# --- The binary alone ---------------------------------------------------------
#
# `--target binary --output type=local,dest=DIR` writes DIR/pgsnare.
FROM scratch AS binary
COPY --from=build /out/pgsnare /pgsnare

# --- The image ----------------------------------------------------------------
#
# The base holds CA certificates and the files that name users. It also holds
# a shell (busybox): that is the owner's choice of this base. The package
# manager of the base, and the libraries only it uses, are removed below.
# Nothing installs a package at run time: the process is not root, holds no
# capability and has a read-only root filesystem when started as the chart
# and the examples start it.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS image

LABEL org.opencontainers.image.title="pgsnare" \
      org.opencontainers.image.description="A PostgreSQL proxy that detects data theft with honeytokens" \
      org.opencontainers.image.source="https://github.com/guidorugo/pgsnare" \
      org.opencontainers.image.licenses="Apache-2.0"

# pgsnare is static, with its own TLS library, and needs from the base only
# the CA certificates and the files that name users. Remove the package
# manager (apk-tools, with its library libapk) and the libraries that only
# it uses: OpenSSL (libssl3, libcrypto3, and ssl_client, the TLS helper of
# busybox, which comes with libssl3) and zlib. They carry most of the
# advisories that the scan of the image finds in the base, and nothing in
# the image needs them once the image is built.
#
# The CA certificates came in as a dependency of apk-tools, so they are
# first named on their own, with the version the base holds, from the
# installed package: otherwise removing apk-tools would remove them too.
# When the base digest above is raised to one with other certificates, the
# build stops here, and the version is raised with it. The database of
# installed packages (/lib/apk/db) is kept, so a scanner and an SBOM still
# see what the image holds. No cache is kept.
RUN set -eu; \
    apk add --no-cache 'ca-certificates-bundle=20261020-r0'; \
    apk del --no-cache apk-tools libapk libssl3 libcrypto3 ssl_client zlib; \
    test ! -e /sbin/apk; \
    test -s /etc/ssl/certs/ca-certificates.crt; \
    test -s /lib/apk/db/installed

# The user and the home directory that the image names. Added while the image
# is built, and not at run time. No package is installed: the CA certificates
# come with the base.
RUN set -eu; \
    addgroup -g 65532 -S nonroot; \
    adduser -u 65532 -G nonroot -S -H -h /home/nonroot -s /sbin/nologin nonroot; \
    install -d -o 65532 -g 65532 -m 0700 /home/nonroot

# Owned by root and not writable, so the process cannot replace it.
COPY --from=build --chown=0:0 --chmod=0555 /out/pgsnare /usr/local/bin/pgsnare

# The licences that go with every copy of the code the binary holds: the
# notices of the packages it depends on, and the licence of the
# repository, which covers the crates of the repository among them.
COPY --from=build --chown=0:0 --chmod=0644 /out/THIRD-PARTY-NOTICES /usr/share/doc/pgsnare/THIRD-PARTY-NOTICES
COPY --from=build --chown=0:0 --chmod=0644 /out/LICENSE /usr/share/doc/pgsnare/LICENSE

# A number and not a name: Kubernetes can check that a number is not 0, and
# cannot check a name. This is the user `nonroot` made above.
USER 65532:65532

# The client port of the example configuration. The admin and metrics
# listeners stay on the loopback interface and are not named here.
EXPOSE 5432

# pgsnare stops on SIGTERM: it lets open sessions finish within
# `shutdown.grace_period` and ends with status 0.
STOPSIGNAL SIGTERM

# Exec form, so no shell runs for the check. It asks the admin listener
# on the loopback interface whether the proxy works, reads no file, and
# takes 2 seconds at most.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --start-interval=1s --retries=3 \
    CMD ["/usr/local/bin/pgsnare", "healthcheck"]

# Mount the configuration at /etc/pgsnare, readable by user 65532 and by
# nobody else: pgsnare refuses a configuration, token file or key that
# other users can read.
ENTRYPOINT ["/usr/local/bin/pgsnare"]
CMD ["run", "--config", "/etc/pgsnare/pgsnare.yaml"]

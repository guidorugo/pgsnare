# SPDX-License-Identifier: Apache-2.0
#
# The pgsnare image: one static binary on a base without a shell and without
# a package manager.
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

# musl-tools compiles the C code that pgsnare links (its cryptography
# library) against musl. clang provides libclang, which the code generator
# of the optional SQL parser needs.
#
# musl-gcc reads the headers of musl and no others. The C code also includes
# headers of the Linux kernel, which do not depend on the C library, so the
# three directories that hold them are linked into the directory of musl.
RUN set -eu; \
    apt-get update; \
    apt-get install --yes --no-install-recommends musl-tools clang; \
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
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# A static binary for the architecture of this machine, with the default
# features and exactly the dependencies of Cargo.lock. The build fails
# unless the result asks for no interpreter and no shared library.
RUN set -eu; \
    case "$(uname -m)" in \
        x86_64) target=x86_64-unknown-linux-musl ;; \
        aarch64) target=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    cargo build --release --locked --package pgsnare --bin pgsnare --target "$target"; \
    install -D --mode 0555 "target/$target/release/pgsnare" /out/pgsnare; \
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
# The base holds CA certificates, time zone data and the files that name
# users. It has no shell, no package manager and no C library.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS image

LABEL org.opencontainers.image.title="pgsnare" \
      org.opencontainers.image.description="A PostgreSQL proxy that detects data theft with honeytokens" \
      org.opencontainers.image.source="https://github.com/guidorugo/pgsnare" \
      org.opencontainers.image.licenses="Apache-2.0"

# Owned by root and not writable, so the process cannot replace it.
COPY --from=build --chown=0:0 --chmod=0555 /out/pgsnare /usr/local/bin/pgsnare

# A number and not a name: Kubernetes can check that a number is not 0, and
# cannot check a name. This is the user `nonroot` of the base.
USER 65532:65532

# The client port of the example configuration. The admin and metrics
# listeners stay on the loopback interface and are not named here.
EXPOSE 5432

# pgsnare stops on SIGTERM: it lets open sessions finish within
# `shutdown.grace_period` and ends with status 0.
STOPSIGNAL SIGTERM

# Exec form, because there is no shell. The check asks the admin listener
# on the loopback interface whether the proxy works, reads no file, and
# takes 2 seconds at most.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --start-interval=1s --retries=3 \
    CMD ["/usr/local/bin/pgsnare", "healthcheck"]

# Mount the configuration at /etc/pgsnare, readable by user 65532 and by
# nobody else: pgsnare refuses a configuration, token file or key that
# other users can read.
ENTRYPOINT ["/usr/local/bin/pgsnare"]
CMD ["run", "--config", "/etc/pgsnare/pgsnare.yaml"]

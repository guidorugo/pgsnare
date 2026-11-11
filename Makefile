# SPDX-License-Identifier: Apache-2.0
#
# Every target runs inside the development image (Dockerfile.dev), as the
# calling user. The host needs only Docker and make.
#
#   make image    build the development image, unless it already exists
#   make build    build the workspace
#   make test     run the unit tests
#   make lint     check the repository rules and formatting, and run clippy
#                 with warnings denied
#   make fmt      format the code
#   make deny     check advisories, licences and sources of every dependency
#   make scan     scan for secrets and private network addresses
#   make itest    run the integration tests against PostgreSQL 15 to 18
#   make fuzz     run every fuzz target for FUZZ_SECONDS each
#   make bench    run the benchmarks
#   make shell    open a shell in the development image (commands can be piped in)
#
# Variables:
#   JOBS          parallel build jobs and test threads (default: all CPUs)
#   CARGO_CACHE   cargo's download cache, kept outside the source tree
#   LOCKED        `--locked` by default, so a build never changes Cargo.lock.
#                 After changing a dependency, run `make build LOCKED=` once
#                 and commit the updated Cargo.lock.
#   FUZZ_SECONDS  time to fuzz each target (default 30). FUZZ_CRATE and
#                 FUZZ_TARGET narrow the run to one crate or one target.
#   BENCH_ARGS    extra arguments for `cargo bench`
#   ITEST_PROJECT the Compose project name of the integration tests
#                 (default pgsnare-itest)

DOCKER ?= docker
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
CARGO_CACHE ?= $(HOME)/.cache/pgsnare/cargo
LOCKED ?= --locked
ITEST_PROJECT ?= pgsnare-itest

# The tag follows the content of Dockerfile.dev, so changing the Dockerfile
# yields a new image instead of silently reusing a stale one.
DEV_IMAGE ?= pgsnare-dev:$(shell cksum Dockerfile.dev | cut -d' ' -f1)

# Allocate a terminal only when there is one, so `make shell` also works
# with commands piped to it.
TTY := $(shell test -t 0 && echo --tty)

RUN = $(DOCKER) run --rm --init \
	--user "$(shell id -u):$(shell id -g)" \
	--cap-drop ALL \
	--security-opt no-new-privileges \
	--env HOME=/tmp \
	--env CARGO_HOME=/cargo \
	--env CARGO_BUILD_JOBS=$(JOBS) \
	--env RUST_TEST_THREADS=$(JOBS) \
	--volume "$(CARGO_CACHE):/cargo" \
	--volume "$(CURDIR):/work" \
	--workdir /work

# `make scan` reads the git history. In a linked git worktree the history
# lives outside the source tree, so it is mounted too, read-only and at the
# path git expects. Without git on the host, the history is not scanned.
GIT_COMMON_DIR := $(shell git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)
GIT_HISTORY := $(if $(GIT_COMMON_DIR),--volume "$(GIT_COMMON_DIR):$(GIT_COMMON_DIR):ro")

.PHONY: image build test lint fmt deny scan itest fuzz bench shell cargo-cache

image:
	@$(DOCKER) image inspect $(DEV_IMAGE) >/dev/null 2>&1 \
		|| $(DOCKER) build --build-arg CARGO_BUILD_JOBS=$(JOBS) --tag $(DEV_IMAGE) - < Dockerfile.dev

# Created up front so Docker does not create it as root.
cargo-cache:
	@mkdir -p "$(CARGO_CACHE)"

build: image cargo-cache
	$(RUN) $(DEV_IMAGE) cargo build --workspace $(LOCKED)

test: image cargo-cache
	$(RUN) $(DEV_IMAGE) cargo test --workspace $(LOCKED)

lint: image cargo-cache
	$(RUN) $(DEV_IMAGE) scripts/check-repo.sh
	$(RUN) $(DEV_IMAGE) cargo fmt --all --check
	$(RUN) $(DEV_IMAGE) cargo clippy --workspace --all-targets $(LOCKED) -- -D warnings
	$(RUN) $(DEV_IMAGE) cargo clippy --workspace --all-targets --no-default-features $(LOCKED) -- -D warnings

fmt: image cargo-cache
	$(RUN) $(DEV_IMAGE) cargo fmt --all

deny: image cargo-cache
	$(RUN) $(DEV_IMAGE) scripts/deny.sh

scan: image cargo-cache
	$(RUN) $(DEV_IMAGE) scripts/scan/selftest.sh
	$(RUN) $(GIT_HISTORY) --env SCAN_REQUIRE_HISTORY $(DEV_IMAGE) scripts/scan/run.sh

# The databases and the test client are containers of their own, started
# with Docker Compose. Nothing publishes a host port.
itest:
	DOCKER="$(DOCKER)" ITEST_PROJECT="$(ITEST_PROJECT)" tests/itest.sh

fuzz: image cargo-cache
	$(RUN) --env FUZZ_SECONDS --env FUZZ_CRATE --env FUZZ_TARGET $(DEV_IMAGE) scripts/fuzz.sh

bench: image cargo-cache
	$(RUN) $(DEV_IMAGE) cargo bench --workspace $(LOCKED) $(BENCH_ARGS)

shell: image cargo-cache
	$(RUN) --interactive $(TTY) $(DEV_IMAGE) bash

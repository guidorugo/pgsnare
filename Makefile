# SPDX-License-Identifier: Apache-2.0
#
# Every target runs inside the development image (Dockerfile.dev), as the
# calling user. The host needs only Docker and make.
#
#   make image    build the development image, unless it already exists
#   make build    build the workspace
#   make test     run the unit tests
#   make lint     check formatting and run clippy with warnings denied
#   make shell    open a shell in the development image (commands can be piped in)
#
# Variables:
#   JOBS          parallel build jobs and test threads (default: all CPUs)
#   CARGO_CACHE   cargo's download cache, kept outside the source tree
#   LOCKED        `--locked` by default, so a build never changes Cargo.lock.
#                 After changing a dependency, run `make build LOCKED=` once
#                 and commit the updated Cargo.lock.

DOCKER ?= docker
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
CARGO_CACHE ?= $(HOME)/.cache/pgsnare/cargo
LOCKED ?= --locked

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

.PHONY: image build test lint shell cargo-cache

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
	$(RUN) $(DEV_IMAGE) cargo fmt --all --check
	$(RUN) $(DEV_IMAGE) cargo clippy --workspace --all-targets $(LOCKED) -- -D warnings

shell: image cargo-cache
	$(RUN) --interactive $(TTY) $(DEV_IMAGE) bash

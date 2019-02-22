#!/usr/bin/env bash

set -e
set -x

# If no target specified, run a normal cargo build and format check
if [ -z "${TARGET}" ]; then
    cargo build --verbose
    cargo fmt -- --check
# Cross doesn't have support for ios targets, so manually add/build them with cargo
elif [ "$IOS" = 1 ]; then
    rustup target add "$TARGET"
    cargo build --target "$TARGET"
# Otherwise use cross to build for the specified argument
else
    cross build --target "$TARGET"
fi

# Only run unit tests if architecture specifies that we should
if [ "$TEST" = 1 ]; then
    if [ -z "${TARGET}" ]; then
        cargo test --verbose
    else
        cross test --target "$TARGET"
    fi
fi
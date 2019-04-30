#!/usr/bin/env bash

set -e
set -x

if [ "${TRAVIS_PULL_REQUEST_BRANCH:-$TRAVIS_BRANCH}" != "master" ] && [ -z "${TARGET}" ]; then
    REMOTE_URL="$(git config --get remote.origin.url)"
    cargo install critcmp

    # Clone the repository fresh..for some reason checking out master fails
    # from a normal PR build's provided directory
    cd ${TRAVIS_BUILD_DIR}/..
    git clone ${REMOTE_URL} "${TRAVIS_REPO_SLUG}-bench"
    cd  "${TRAVIS_REPO_SLUG}-bench"

    # The Travis environment variables behave like so:
    # TRAVIS_BRANCH
    #   - if PR build, this is the pr base branch
    #   - if push build, this is the branch that was pushed
    # TRAVIS_PULL_REQUEST_BRANCH
    #   - if PR build, this is the "target" of the pr, i.e. not the base branch
    #   - if push build, this is blank
    #
    # Example:
    # You open a PR with base `master`, and PR branch `foo`
    # During a PR build:
    #     TRAVIS_BRANCH=master
    #     TRAVIS_PULL_REQUEST_BRANCH=foo
    # During a push build:
    #     TRAVIS_BRANCH=foo
    #     TRAVIS_PULL_REQUEST_BRANCH=

    # Bench the pull request base or master
    if [ -n "$TRAVIS_PULL_REQUEST_BRANCH" ]; then
      git checkout -f "$TRAVIS_BRANCH"
    else # this is a push build
      # This could be replaced with something better like asking git which
      # branch is the base of $TRAVIS_BRANCH
      git checkout -f master
    fi
    cargo bench -- --save-baseline master-benchmark
    # Bench the current commit that was pushed
    git checkout -f "${TRAVIS_PULL_REQUEST_BRANCH:-$TRAVIS_BRANCH}"
    cargo bench -- --save-baseline current-benchmark
    # compare the before/after results; filter out anything less than 2% change
    critcmp master-benchmark current-benchmark -t 2
fi

#!/bin/sh
# SPDX-FileCopyrightText: 2026 Yuao Ma
#
# SPDX-License-Identifier: Apache-2.0

# Golden test driver for the structured packet tracer, shared by the autotools
# and CMake builds (Bazel uses the cmd_diff_test rule in BUILD.bazel instead).
#
# For each pipeline, runs the test_packet_trace binary on
# <testdata_dir>/<pipeline>.json and diffs its output against the checked-in
# <testdata_dir>/<pipeline>.trace golden file.
#
# Usage: run_packet_trace_test.sh <binary> <testdata_dir> <pipeline>...
#
# The automake test harness cannot pass arguments to a test, so the same three
# inputs may instead be supplied through the environment:
#   PACKET_TRACE_BIN, PACKET_TRACE_TESTDATA, PACKET_TRACE_PIPELINES
# (the last one a space-separated list).
#
# Set BM_UPDATE_GOLDEN=1 to overwrite the golden files instead of diffing.

set -e

if [ $# -eq 0 ]; then
    set -- "$PACKET_TRACE_BIN" "$PACKET_TRACE_TESTDATA" $PACKET_TRACE_PIPELINES
fi

if [ $# -lt 3 ]; then
    echo "Usage: $0 <binary> <testdata_dir> <pipeline>..." >&2
    exit 1
fi

BINARY=$1
TESTDATA_DIR=$2
shift 2

if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY is not an executable" >&2
    exit 1
fi

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# Drops trailing blank lines, so that the comparison matches the Bazel
# cmd_diff_test rule, which ignores a trailing newline difference.
strip_trailing_blank_lines() {
    awk '{ if ($0 == "") { blanks++ } else { while (blanks-- > 0) print ""; blanks = 0; print } }' "$1"
}

status=0
for pipeline in "$@"; do
    json="$TESTDATA_DIR/$pipeline.json"
    golden="$TESTDATA_DIR/$pipeline.trace"
    actual="$TMPDIR_TEST/$pipeline.trace"

    if ! "$BINARY" "$pipeline" "$json" > "$actual"; then
        echo "FAIL: $pipeline: test_packet_trace exited with an error" >&2
        status=1
        continue
    fi

    if [ "$BM_UPDATE_GOLDEN" = "1" ]; then
        cp "$actual" "$golden"
        echo "UPDATED: $golden"
        continue
    fi

    strip_trailing_blank_lines "$golden" > "$TMPDIR_TEST/expected.txt"
    strip_trailing_blank_lines "$actual" > "$TMPDIR_TEST/actual.txt"
    if diff -u --label "$golden" --label "$actual" \
        "$TMPDIR_TEST/expected.txt" "$TMPDIR_TEST/actual.txt"; then
        echo "PASS: $pipeline"
    else
        echo "FAIL: $pipeline: output differs from $golden" >&2
        status=1
    fi
done

exit $status

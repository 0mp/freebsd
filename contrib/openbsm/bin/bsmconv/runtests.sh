#!/bin/sh

TEST_DIR=tests/
BIN=./conv.out

for TEST_FILE in "$TEST_DIR"*.input; do
    cat "$TEST_FILE" | "$BIN"
done

#!/bin/sh

TEST_DIR=tests/
BIN=./conv.out

if [ "$1" = "-m" ]; then
	make
fi

for TEST_FILE in "$TEST_DIR"*.input; do
    cat "$TEST_FILE" | "$BIN"
done

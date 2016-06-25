#!/bin/sh

TEST_DIR=tests/
MAKEFILE_DIR=../../../../usr.bin/bsmconv/
BIN=${MAKEFILE_DIR}bsmconv
MAKEFILE=${MAKEFILE_DIR}Makefile

if [ "$1" = "-m" ]; then
	CWD=$(pwd)
	cd "$MAKEFILE_DIR"
	make
	cd "$CWD"
fi

echo ==================== TESTS ==========================
for TEST_FILE in "$TEST_DIR"*.input; do
    cat "$TEST_FILE" | "$BIN"
done

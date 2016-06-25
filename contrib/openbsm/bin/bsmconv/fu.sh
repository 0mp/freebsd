#!/bin/sh

TEST_DIR=tests/
MAKEFILE_DIR=../../../../usr.bin/bsmconv/
BIN=${MAKEFILE_DIR}bsmconv
MAKEFILE=${MAKEFILE_DIR}Makefile

fu_make() {
        local CWD
        CWD=$(pwd)
        cd "$MAKEFILE_DIR"
        make
        cd "$CWD"
}

fu_run_tests() {
    if [ "$1" = "-m" ]; then
        fu_make
    fi
    echo ==================== TESTS ==========================
    for TEST_FILE in "$TEST_DIR"*.input; do
        cat "$TEST_FILE" | "$BIN"
    done
}


case "$1" in
    t|test|tests)
        fu_run_tests "$2"
        ;;
    m|make)
        fu_make
        ;;
    *)
        printf "%s\n%s\n" \
            "The game of chess is like a sword fight." \
            "You must think first before you move."
        exit 1
        ;;
esac





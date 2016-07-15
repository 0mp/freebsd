# Compile

    ./fu m

# Tests

## Run all tests

    ./fu t

## Run all tests with debugging messages

    ./fu tv -vvvvvv

## Run one specified test

For example 1.input from the positive test suit.

    ./fu rv -vvvvvv tests/positive/1.input


## Pretty print the notes on Linux Audit

    node NOTES_ON_LINUX_AUDIT.js | python -m json.tool

#!/usr/bin/env bash

source "./helpers.bash"

if grep -r "sleep" | grep -v "00-no-sleep" | grep -v "helpers.bash"; then
    echo "Please do not use sleep, consider using one of the wait helper functions."
    echo "If none of the provided wait functions fit your use case please discuss your use case on Slack and / or file a bug."
    exit 1
fi
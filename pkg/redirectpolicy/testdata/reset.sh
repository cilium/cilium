#!/bin/sh
set -eu
cd "$(dirname "${BASH_SOURCE[0]}")"
test -f actual_before.tables && mv -vf actual_before.tables expected_before.tables
test -f actual.tables && mv -vf actual.tables expected.tables
test -f actual_after.tables && mv -vf actual_after.tables expected_after.tables

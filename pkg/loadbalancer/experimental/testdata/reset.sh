#!/usr/bin/env bash
#
# Reset the expected data files in the test cases.
#
cd "$(dirname "${BASH_SOURCE[0]}")"
for tc in */; do
  test -f "${tc}/actual.maps" && mv -vf "${tc}/actual.maps" "${tc}/expected.maps"
  test -f "${tc}/actual.tables" && mv -vf "${tc}/actual.tables" "${tc}/expected.tables"
done


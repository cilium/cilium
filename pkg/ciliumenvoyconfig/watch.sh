#!/usr/bin/env bash
#
# watch.sh watches the current and testdata directories and will
# either recompile or execute the test for the changes test script.
# This is useful when working on a test case as "go test" can be slow
# due to slow linking as we pull in the client-go.
#
# https://github.com/kubernetes/kubernetes/issues/127888 is an issue
# for making client-go lighter that should improve the binary size and
# compilation times.

set -ux
go test -c || exit 1

inotifywait -e close_write -m . testdata |
while read -r directory events filename; do
  case "$directory" in
    ./)
      go test -c && ./ciliumenvoyconfig.test -test.v -test.failfast
      ;;
    testdata/) 
      ./ciliumenvoyconfig.test -test.run TestScript/$filename -test.v
      ;;
  esac
done


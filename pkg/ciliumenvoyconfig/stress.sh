#!/usr/bin/env bash
set -eux
[ ! -f $HOME/go/bin/stress ] && go install golang.org/x/tools/cmd/stress@latest

go test -c -o stress.test
$HOME/go/bin/stress -count 500 ./stress.test
rm stress.test

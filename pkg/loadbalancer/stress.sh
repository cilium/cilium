#!/usr/bin/env bash
set -eux
[ ! -f $HOME/go/bin/stress ] && go install golang.org/x/tools/cmd/stress@latest

DIRS="tests redirectpolicy reconciler healthserver"

for dir in $DIRS; do
  pushd $dir
  go test -c -o stress.test
  $HOME/go/bin/stress -count 500 ./stress.test
  rm stress.test
  popd
done

#!/usr/bin/env bash

source ./helpers.bash

if grep --include \*.go -r 'log\.' ../ | grep -v vendor \
  | grep -v contrib \
  | grep -v logging.go \
  | grep -F "\n"; then
  abort "found newline(s) in log call(s), please remove ending \n"
fi

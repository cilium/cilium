#!/bin/bash

TOPDIR=$(git rev-parse --show-toplevel)

exit_code=0
errs=$(ineffassign $TOPDIR)

# Filter out results which we want to ignore explicitly, because ineffassign
# doesn't support ignoring errors yet
# https://github.com/gordonklaus/ineffassign/issues/27
while read -r err; do
	info=($(echo $err | tr ":" "\n"))
	filename=${info[0]}
	line=${info[1]}
	content=$(sed "${line}q;d" $filename)

	if [[ $content != *"// ineffassign: ignore"* ]]; then
		echo $err
		exit_code=1
	fi
done <<< "$errs"

exit $exit_code

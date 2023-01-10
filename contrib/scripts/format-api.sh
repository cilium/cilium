#!/bin/bash

function format() {
	echo "formatting ${1}"
	find "${1}" -type f -name "*.go" -print | xargs goimports -w
}

for arg in "$@"
do
		format "${arg}"
done

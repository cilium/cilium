#!/bin/bash

# Ensure sort order doesn't depend on locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

function extract_authors() {
	authors=$(git shortlog --summary | awk '{$1=""; print $0}' | sed -e 's/^ //')
	IFS=$'\n'
	pad=$(printf '%0.1s' " "{1..60})
	padlen=40
	for i in $authors; do
		name=$(git log --use-mailmap --author="$i" --format="%aN" | head -1)
		mail=$(git log --use-mailmap --author="$i" --format="%aE" | head -1)
		printf '%s' "$name"
		printf '%*.*s' 0 $((padlen - ${#name})) "$pad"
		printf '%s\n' "$mail"
	done
}

extract_authors | sort -u

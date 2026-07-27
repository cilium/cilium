#!/usr/bin/env bash

# Ensure sort order doesn't depend on locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

function extract_authors() {
	authors=$(git shortlog --summary \
		  | awk '{$1=""; print $0}' \
		  | sed -e 's/^ //' \
			-e '/vagrant/d')

	# Iterate $authors by line
	IFS=$'\n'
	for i in $authors; do
		git log --use-mailmap --author="$i" --format="%<|(40)%aN%aE" | head -1
	done
}

extract_authors | sort -u

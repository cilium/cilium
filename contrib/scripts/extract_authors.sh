#!/bin/bash

# Ensure sort order doesn't depend on locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LC_COLLATE=C

function extract_authors() {
	git log --use-mailmap --format="%<|(40)%aN%aE" | sort -fu | uniq -w 40 | grep -v -e vagrant -e '\[bot\]'
}

extract_authors

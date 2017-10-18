#!/bin/bash

function extract_authors() {
	authors=$(git shortlog --summary | awk '{$1=""; print $0}' | sed -e 's/^ //')
	IFS=$'\n'
	for i in $authors; do
		git log --use-mailmap --author="$i" | grep Author | head -1 | sed -e 's/Author: //'
	done
}

extract_authors | uniq | sort

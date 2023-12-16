#!/usr/bin/env bash

# Ensure sort order doesn't depend on locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

function extract_authors() {
	git log --use-mailmap  --format="%<|(40)%aN%aE"
}

extract_authors #!/usr/bin/env bash

# Ensure sort order doesn't depend on locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

function extract_authors() {
	git log --use-mailmap  --format="%<|(40)%aN%aE" |sort -u
}

extract_authors


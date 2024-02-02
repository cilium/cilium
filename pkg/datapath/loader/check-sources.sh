#!/usr/bin/env bash

set -efu

#
# This simple awk command extracts file names from the definition of the
# __source_file_name_to_id function. This is the list of file names which
# are currently assigned a numerical ID.
#
defined_files=$(
	echo ${BPF_SOURCE_NAMES_TO_IDS} | xargs -n1 \
		awk -F: '/@@ source files list begin/{found=1; next}
		/@@ source files list end/{exit}
		{if (!found || !/_strcase_/) next}
		{gsub(/.* |"|\)|;/, "", $1); print $1}
		' | sort -u
)

#
# Now let's find all the names defined inside the go source file
#
defined_files_go=$(
	echo ${GO_SOURCE_NAMES_TO_IDS} | xargs -n1 \
		awk '/@@ source files list begin/{found=1; next}
		{if (!found) next}
		/@@ source files list end/{exit}
		{if (!/: /) next}
		{gsub(/"|,/, "", $2); print $2}
		' | sort -u
)
if [ "$defined_files" != "$defined_files_go" ]; then
	echo "File lists in ${BPF_SOURCE_NAMES_TO_IDS} and ${GO_SOURCE_NAMES_TO_IDS} aren't same, please sync" >&2
	exit 1
fi

#
# Both lists should be the same
#

#
# Now we need to find all the C files in the bpf/ directory and all header
# files in the bpf/lib/ directory which are using one of send_drop_notify*
# functions.
#
all_files=$(find bpf/ -maxdepth 1 -name '*.c'; find bpf/lib/ -maxdepth 1 -name '*.h')
required_files=$(
	grep -e '\<send_drop_notify\(\|_error\|_ext\|_error_ext\)\>' $all_files |
	cut -f1 -d: |
	sort -u |
	xargs -n1 basename
)

#
# Check that all files which use send_drop_notify* are defined
#
retval=0
for f in $required_files; do
	if ! grep --silent -w "$f" <<<"$defined_files"; then
		echo "$0: $f is not defined, please add its mapping to ${BPF_SOURCE_NAMES_TO_IDS}" >&2
		retval=1
	fi
done

#
# Check that all defined files actually use send_drop_notify*
#
for f in $defined_files; do
	if ! grep --silent -w "$f" <<<"$required_files"; then
		echo "$0: $f is not using send_drop_notify*, please remove it from ${BPF_SOURCE_NAMES_TO_IDS}" >&2
		retval=1
	fi
done

exit $retval

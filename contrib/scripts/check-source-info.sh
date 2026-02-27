#!/usr/bin/env bash

set -euo pipefail

bpf_source_info=$(grep --exclude-dir=vendor/ --include='*.h' -Rl "@@ source files list begin" | tr '\n' ' ')
go_source_info=$(grep --exclude-dir=vendor/ --include='*.go' -Rl "@@ source files list begin" | tr '\n' ' ')

#
# This simple awk command extracts file names from the definition of the
# __id_for_file function. This is the list of file names which
# are currently assigned a numerical ID.
#
defined_files=$(
	echo ${bpf_source_info} |
	xargs -n1 awk -F: '/@@ source files list begin/{found=1; next}
	/@@ source files list end/{exit}
	{if (!found || !/_strcase_/) next}
	/\/\*/{in_comment=1}
	/\*\//{in_comment=0; next}
	{if (in_comment) next}
	{gsub(/.* |"|\)|;/, "", $1); print $1}' |
	sort -u
)

#
# Now let's find all the names defined inside the go source file
#
defined_files_go=$(
	echo ${go_source_info} |
	xargs -n1 awk '/@@ source files list begin/{found=1; next}
	{if (!found) next}
	/@@ source files list end/{exit}
	{sub(/[ \t]*\/\/.*/, "")}
	{if (!/: / || !NF) next}
	{gsub(/"|,/, "", $2); print $2}' |
	sort -u
)
if [ "$defined_files" != "$defined_files_go" ]; then
	echo "File lists in ${bpf_source_info} and ${go_source_info} aren't same, please sync" >&2
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
required_files=$(
	grep -E 'send_drop_notify(|_error|_ext|_error_ext)?|update_(trace_)?metrics|send_trace_notify' bpf/*.c bpf/*.h bpf/lib/*.h |
	cut -f1 -d: |
	sort -u |
	grep -v "metrics.h" |
	xargs -n1 basename
)

#
# Check that all files using macros depending on __MAGIC_FILE__ are defined.
#
retval=0
for f in $required_files; do
	if ! grep --silent -w "$f" <<<"$defined_files"; then
		echo "$0: $f is not defined, please add its mapping to ${bpf_source_info}" >&2
		retval=1
	fi
done

#
# Check that all defined files actually use macros depending on __MAGIC_FILE__.
#
for f in $defined_files; do
	if ! grep --silent -w "$f" <<<"$required_files"; then
		echo "$0: $f is not using send_drop_notify*, update_(trace_)metrics or send_trace_notify, please remove it from ${bpf_source_info}" >&2
		retval=1
	fi
done

exit $retval

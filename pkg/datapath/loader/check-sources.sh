#! /bin/bash -efu

#
# This simple awk command extracts file names from the definition of the
# __source_file_name_to_id function. This is the list of file names which
# are currently assigned a numerical ID.
#
defined_files=$(
	awk -F: '/^__source_file_name_to_id/{found=1; next}
		/return 0/{exit}
		{if (!found || !/_strcase_/) next}
		{gsub(/.* |"|\)|;/, "", $1); print $1}
		' bpf/source_names_to_ids.h
)


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
		echo "$0: $f is not defined, please add its mapping to bpf/source_names_to_ids.h" >&2
		retval=1
	fi
done

#
# Check that all defined files actually use send_drop_notify*
#
retval=0
for f in $defined_files; do
	if ! grep --silent -w "$f" <<<"$required_files"; then
		echo "$0: $f is not using send_drop_notify*, please remove it from bpf/source_names_to_ids.h" >&2
		retval=1
	fi
done

exit $retval

#! /bin/bash -efu

#
# This simple awk command extracts file names from the sourceNameToId map definition
#
defined_files=$(
  awk -F: '/^var sourceNameToId/{found=1; next} {if (!found) next} /^}/{exit} {gsub(/"|\t/, "", $1); print $1}' pkg/datapath/loader/compile.go
)

#
# Now we need to find all the C files in the bpf/ directory
# and check if all of them were defined in the map
#
required_files=$(
	find bpf/ -maxdepth 1 -name '*.c' | xargs -n1 basename
)

retval=0
for f in $required_files; do
	if ! grep --silent -w "$f" <<<"$defined_files"; then
		echo "$0: $f is not defined, add its mapping to the sourceNameToId map" >&2
		retval=1
	fi
done

exit $retval

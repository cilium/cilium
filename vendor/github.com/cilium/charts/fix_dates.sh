#!/bin/bash

set -eo pipefail

linesWithDate=($(git blame index.yaml --date=iso-strict \
                 | awk '/created/ { print $5; }' \
                 | sed 's/)$//'))

# Lines with the date were overwritten. Take an adjacent line for real date.
dates=($(git blame index.yaml --date=iso-strict \
         | grep -A 1 created \
         | grep -v created \
         | awk '{ print $4 }'))

for i in ${!linesWithDate[@]}; do
    if ! date --date ${dates[$i]} >/dev/null; then
        >&2 echo "unclean git tree, stash all changes before running this script."
        exit 1
    fi

    sed -i "${linesWithDate[$i]}s/\"[^\"]*\"/\"${dates[$i]}\"/" index.yaml
done

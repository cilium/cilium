#!/usr/bin/env bash

set -e

# Ensure sort order doesn't depend on locale
export LANG=C
export LC_ALL=C

for word in "$@"
do
    echo "${word}" >> Documentation/spelling_wordlist.txt
done

sort -u Documentation/spelling_wordlist.txt > Documentation/spelling_wordlist.txt.tmp
mv Documentation/spelling_wordlist.txt.tmp Documentation/spelling_wordlist.txt

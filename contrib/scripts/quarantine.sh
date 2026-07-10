#!/usr/bin/env bash

set -e
set -o pipefail

indent() {
    sed 's/^/  /'
}

main() {
    tmpfile=$(mktemp)
    trap 'rm -f -- $tmpfile' EXIT

    if [ $# -lt 1 ] || [ $# -gt 1 ]; then
        >&2 echo "usage: $0 <focus-phrase>"
        return 1
    fi

    if ! git grep -q "$1"; then
        >&2 echo "Unable to find phrase."
        return 1
    fi

    if ! git diff --quiet || ! git diff --quiet --cached; then
        >&2 echo "Local changes in the git tree break this script. Stage your changes to continue."
        return 1
    fi

    files=( $(git grep -l "$1" test/*/*go) )
    for f in "${files[@]}"; do
        commits=( $(git blame $f | grep "$1" |  awk '{ print $1; }') )
        authors=()
        for c in "${commits[@]}"; do
            authors+=( "$(git log -1 $c --pretty='%aN <%aE>')" )
        done

        sed -i '/Quarantine/b; s/\(SkipItIf([^,]*\),\(.*'"$1"'.*\)/\1 || helpers.SkipQuarantined,\2/g' $f
        sed -i '/Quarantine/b; s/\(SkipContextIf([^,]*\),\(.*'"$1"'.*\)/\1 || helpers.SkipQuarantined,\2/g' $f
        sed -i 's/It(\(.*'"$1"'.*\)$/SkipItIf(helpers.SkipQuarantined, \1/g' $f
        sed -i 's/Context(\(.*'"$1"'.*\)$/SkipContextIf(helpers.SkipQuarantined, \1/g' $f

        git add $f || ( >&2 echo "Unable to disable test, maybe the declaration is multi-line?" && return 1 )

        >$tmpfile echo "test/$(basename $f | sed 's/\.go//'): Quarantine '$1'"
        >>$tmpfile echo
        for a in "${authors[@]}"; do
            if grep -q "$a" $tmpfile; then
                continue
            fi
            >>$tmpfile echo "CC: $a"
        done
        git commit --signoff --quiet --message "$(cat $tmpfile)"
    done
}

main "$@"

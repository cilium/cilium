#!/usr/bin/env bash

source "./helpers.bash"

threshold=5000

fd_open=$(sudo lsof 2>/dev/null | grep cilium | wc -l)

if [[ ${fd_open} -gt ${threshold} ]]; then
    abort "Number of fd open seems abnormal: ${fd_open} (expecting less than ${threshold})"
fi

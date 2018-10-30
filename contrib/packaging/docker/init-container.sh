#!/bin/sh

if [ "${CLEAN_CILIUM_STATE}" = "true" ]; then
    echo "Removing Cilium state..."
    rm -rf /var/run/cilium/state;
fi;
if [ "${CLEAN_CILIUM_STATE}" = "true" ] \
   || [ "${CLEAN_CILIUM_BPF_STATE}" = "true" ]; then
    echo "Removing BPF state..."
    rm -rf /sys/fs/bpf/tc/globals/cilium_* \
           /var/run/cilium/bpffs/tc/globals/cilium_*;
fi

#!/bin/sh

# Check for CLEAN_CILIUM_BPF_STATE and CLEAN_CILIUM_STATE
# is there for backwards compatibility as we've used those
# two env vars in our old kubernetes yaml files.

if [ "${CILIUM_BPF_STATE}" = "true" ] \
   || [ "${CLEAN_CILIUM_BPF_STATE}" = "true" ]; then
	cilium cleanup -f --bpf-state
fi

if [ "${CILIUM_ALL_STATE}" = "true" ] \
    || [ "${CLEAN_CILIUM_STATE}" = "true" ]; then
	cilium cleanup -f --all-state
fi

if [ "${CILIUM_WAIT_BPF_MOUNT}" = "true" ]; then
	until mount | grep "/sys/fs/bpf type bpf"; do echo "BPF filesystem is not mounted yet"; sleep 1; done
fi;

#!/bin/sh

cilium cleanup -f

if [ "${CILIUM_WAIT_BPF_MOUNT}" = "true" ]; then
	until mount | grep bpf; do echo "BPF filesystem is not mounted yet"; sleep 1; done
fi;

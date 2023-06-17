#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -e

DEV="cilium-probe"
LIB="bpf"
RUNDIR="test/bpf/_results"

function cleanup {
	ip link del ${DEV} 2>/dev/null || true
}

if [ ! -e ${RUNDIR}/globals ]; then
	mkdir -p ${RUNDIR}/globals
fi

if [ $(id -u) -ne 0 ]; then
	echo "Must be run as root"
	exit 1
fi

trap cleanup EXIT
ip link add ${DEV} type dummy
${LIB}/run_probes.sh $LIB $RUNDIR 2>/dev/null
for path in $(find $RUNDIR -type f); do
	echo "=> Examining $path..."
	cat $path
done

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -x

trap cleanup EXIT

TMPDIR=cilium-heap-$(date -u '+%Y%m%d-%H%M%S')
mkdir -p $TMPDIR

function cleanup {
	rm -rf $TMPDIR
}

pods=$(kubectl -n kube-system get pods -l k8s-app=cilium | awk '{print $1}' | grep cilium)
IFS=$'\r\n'
for p in $pods; do
	PROFILE=$(kubectl -n kube-system exec -ti $p -- gops pprof-heap 1)
	PROFILE=$(echo $PROFILE | awk '{print $5}')
	kubectl cp kube-system/$p:$PROFILE $TMPDIR/${p}_$(basename $PROFILE)
done

zip -r ${TMPDIR}.zip $TMPDIR

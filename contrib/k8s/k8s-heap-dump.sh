#!/bin/bash
#
# Copyright 2018 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

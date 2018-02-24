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

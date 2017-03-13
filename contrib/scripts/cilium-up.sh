#!/usr/bin/env bash

dir=$(cd $(dirname ${BASH_SOURCE})/../.. && pwd)

function cleanup {
	killall -9 cilium-docker 2> /dev/null
	killall -9 cilium-agent 2> /dev/null
}

trap cleanup EXIT
cleanup

if [ -z $(which clang) ]; then
	echo "Looking for LLVM installation..."
	llvm_dir=$($dir/contrib/scripts/find-llvm.sh)
	echo "Adding $llvm_dir/bin to PATH"
	export PATH="$llvm_dir/bin:$PATH"
fi

sleep 3s

$dir/plugins/cilium-docker/cilium-docker&
$dir/daemon/cilium-agent $*

#!/usr/bin/env bash

dir=$(cd $(dirname ${BASH_SOURCE})/../.. && pwd)

function cleanup {
	docker rm -f "cilium-consul" 2> /dev/null || true
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

docker run -d \
   --name "cilium-consul" \
   -p 8501:8500 \
   -e 'CONSUL_LOCAL_CONFIG={"skip_leave_on_interrupt": true, "disable_update_check": true}' \
   consul:1.1.0 \
   agent -client=0.0.0.0 -server -bootstrap-expect 1

$dir/plugins/cilium-docker/cilium-docker&
$dir/daemon/cilium-agent --kvstore consul --kvstore-opt consul.address=127.0.0.1:8501 $*

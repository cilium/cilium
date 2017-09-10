#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

for img in tgraf/netperf httpd cilium/demo-httpd \
  cilium/demo-client tgraf/nettools borkmann/misc \
  registry busybox:latest quay.io/coreos/etcd:v3.1.0; do
  docker pull $img &
done

for p in `jobs -p`; do
  wait $p
done

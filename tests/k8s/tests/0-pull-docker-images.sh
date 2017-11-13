#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex


for img in borkmann/misc \
  gcr.io/google_samples/gb-redisslave:v1 \
  httpd \
  kubernetes/guestbook:v2 \
  redis; do

  docker pull $img &
done

for p in `jobs -p`; do
  wait $p
done

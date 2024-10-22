#!/usr/bin/env bash

set -o errexit
set -o pipefail

make -C bpf coccicheck | tee /tmp/stdout
exit $(grep -c "^* file " /tmp/stdout)

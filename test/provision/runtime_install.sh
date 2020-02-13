#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

"${PROVISIONSRC}"/dns.sh
# NOTE(mrostecki): Temporary hack until either:
# 1) https://github.com/cilium/packer-ci-build/pull/187 gets merged.
# 2) `bpftool feature filter_in/filter_out` gets upstreamed.
"${PROVISIONSRC}"/bpftool.sh
"${PROVISIONSRC}"/compile.sh
"${PROVISIONSRC}"/wait-cilium.sh

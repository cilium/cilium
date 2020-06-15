#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

update-alternatives \
  --install /usr/sbin/iptables iptables /usr/sbin/iptables-wrapper 100 \
  --slave /usr/sbin/iptables-restore iptables-restore /usr/sbin/iptables-wrapper \
  --slave /usr/sbin/iptables-save iptables-save /usr/sbin/iptables-wrapper && \

update-alternatives \
  --install /usr/sbin/ip6tables ip6tables /usr/sbin/iptables-wrapper 100 \
  --slave /usr/sbin/ip6tables-restore ip6tables-restore /usr/sbin/iptables-wrapper \
  --slave /usr/sbin/ip6tables-save ip6tables-save /usr/sbin/iptables-wrapper

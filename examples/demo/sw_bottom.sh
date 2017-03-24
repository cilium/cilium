#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

run "tail -f /var/log/upstart/cilium.log"

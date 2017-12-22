#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../contrib/shell/util.sh

desc "Run cilium monitor to see events from BPF programs"
run "cilium monitor"

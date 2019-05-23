#!/bin/bash

# generate-feature-headers.sh calls bpftool to generate bpf_features.h header
# file with macros indicating which BPF features are available in the kernel.

TOPDIR=$(git rev-parse --show-toplevel)

sudo bpftool feature probe macros > ${TOPDIR}/bpf/bpf_features.h

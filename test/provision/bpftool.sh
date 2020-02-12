#!/bin/bash

# NOTE(mrostecki): Temporary hack until either:
# 1) https://github.com/cilium/packer-ci-build/pull/187 gets merged.
# 2) `bpftool feature filter_in/filter_out` gets upstreamed.

set -e

git clone --depth 1 -b bpftool https://github.com/cilium/linux.git $HOME/k-bpftool
cd $HOME/k-bpftool/tools/bpf/bpftool
make
sudo make install

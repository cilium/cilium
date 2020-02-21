#!/bin/bash

# NOTE(mrostecki): Temporary hack until either:
# 1) https://github.com/cilium/packer-ci-build/pull/187 gets merged.
# 2) `bpftool feature filter_in/filter_out` gets upstreamed.

set -e

if [ -d "$HOME/k-bpftool" ]; then
    cd $HOME/k-bpftool
    git pull origin bpftool
else
    git clone --depth 1 -b bpftool https://github.com/cilium/linux.git $HOME/k-bpftool
fi
cd $HOME/k-bpftool/tools/bpf/bpftool
make
sudo make install

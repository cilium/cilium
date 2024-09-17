#!/bin/bash

DIRS="afpacket layers pcap pcapgo tcpassembly tcpassembly/tcpreader reassembly routing ip4defrag bytediff macs routing defrag/lcmdefrag"
set -e
export CGO_ENABLED=1
for subdir in $DIRS; do
  pushd $subdir
  sudo -E go test -v -count=1 .
  popd
done

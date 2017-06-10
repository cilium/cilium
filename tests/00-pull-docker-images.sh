#!/bin/bash

for img in tgraf/netperf httpd cilium/demo-httpd \
  cilium/demo-client tgraf/nettools borkmann/misc \
  registry busybox:latest; do
  docker pull $img &
done

for p in `jobs -p`; do
  wait $p
done

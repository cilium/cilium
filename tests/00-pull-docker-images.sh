#!/bin/bash

for img in tgraf/netperf httpd cilium/demo-httpd \
  cilium/demo-client tgraf/nettools borkmann/misc \
  registry busybox:latest quay.io/coreos/etcd:v3.1.0; do
  docker pull $img &
done

for p in `jobs -p`; do
  wait $p
done

#!/bin/bash

set -e

for i in $(seq 1 1000); do
    cilium connectivity test -v
done

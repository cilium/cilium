#!/bin/sh
for d in *; do
    test -f $d/actual.yaml && cp -v $d/actual.yaml $d/expected.yaml && rm -v $d/actual.yaml
done

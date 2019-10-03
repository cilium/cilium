#!/bin/bash

set -e

cd ..
make docker-image

docker tag cilium/cilium:latest $1/cilium/cilium:$2
docker tag cilium/cilium:latest $1/cilium/cilium-dev:$2
docker tag cilium/operator:latest $1/cilium/operator:$2

docker push $1/cilium/cilium:$2
docker push $1/cilium/cilium-dev:$2
docker push $1/cilium/operator:$2

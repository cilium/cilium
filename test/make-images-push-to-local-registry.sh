#!/bin/bash

set -e

cd ..
make docker-image DOCKER_IMAGE_TAG="$2"

docker tag "cilium/cilium:$2" "$1/cilium/cilium:$2"
docker tag "cilium/cilium:$2" "$1/cilium/cilium-dev:$2"
docker tag "cilium/operator:$2" "$1/cilium/operator:$2"
docker tag "cilium/hubble-relay:$2" "$1/cilium/hubble-relay:$2"

docker push "$1/cilium/cilium:$2"
docker push "$1/cilium/cilium-dev:$2"
docker push "$1/cilium/operator:$2"
docker push "$1/cilium/hubble-relay:$2"

cilium_git_version="$(cat GIT_VERSION)"

counter=0
until [ $counter -eq 10 ] || docker image prune -f --all --filter "label=cilium-sha=${cilium_git_version%% *}"; do
	((counter++))
	sleep 6
done

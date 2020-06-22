#!/bin/bash

set -e

cd ..
make docker-image DOCKER_IMAGE_TAG="$2"

docker tag "cilium/cilium:$2" "$1/cilium/cilium:$2"
docker tag "cilium/cilium:$2" "$1/cilium/cilium-dev:$2"
docker tag "cilium/operator:$2" "$1/cilium/operator:$2"
docker tag "cilium/operator-generic:$2" "$1/cilium/operator-generic:$2"
docker tag "cilium/operator-aws:$2" "$1/cilium/operator-aws:$2"
docker tag "cilium/operator-azure:$2" "$1/cilium/operator-azure:$2"
docker tag "cilium/hubble-relay:$2" "$1/cilium/hubble-relay:$2"

docker push "$1/cilium/cilium:$2"
docker push "$1/cilium/cilium-dev:$2"
docker push "$1/cilium/operator:$2"
docker push "$1/cilium/operator-generic:$2"
docker push "$1/cilium/operator-aws:$2"
docker push "$1/cilium/operator-azure:$2"
docker push "$1/cilium/hubble-relay:$2"

cilium_git_version="$(cat GIT_VERSION)"

counter=0
exitCode=1
until [ $exitCode -eq 0 ] || [ $counter -eq 10 ]; do
	docker image prune -f --all --filter "label=cilium-sha=${cilium_git_version%% *}" && exitCode=$? || exitCode=$?
	counter=$((counter+1))
	sleep 6
done

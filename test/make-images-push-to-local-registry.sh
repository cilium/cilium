#!/bin/bash

set -e

cd ..
DOCKER_BUILDKIT=1 make docker-image DOCKER_IMAGE_TAG="$2"

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

# push startup-script image with proper tag to repo
nodeInitTag="af2a99046eca96c0138551393b21a5c044c7fe79"
docker pull "cilium/startup-script:$nodeInitTag"
docker tag "cilium/startup-script:$nodeInitTag" "$1/cilium/startup-script:$nodeInitTag"
docker push "$1/cilium/startup-script:$nodeInitTag"

cilium_git_version="$(cat GIT_VERSION)"

counter=0
exitCode=1
until [ $exitCode -eq 0 ] || [ $counter -eq 10 ]; do
	docker image prune -f --all --filter "label=cilium-sha=${cilium_git_version%% *}" && exitCode=$? || exitCode=$?
	counter=$((counter+1))
	sleep 6
done

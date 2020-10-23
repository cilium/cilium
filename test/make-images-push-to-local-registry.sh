#!/bin/bash

set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=gke/locking.sh
source "${script_dir}/gke/locking.sh"

pushd "${script_dir}/.."
lock
trap unlock EXIT

DOCKER_BUILDKIT=1 make docker-images-all DOCKER_IMAGE_TAG="$2" DOCKER_FLAGS="$3"

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
nodeInitTag="62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8"
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

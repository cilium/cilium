#!/bin/bash
set -e

IMAGE_NAME=${1:-}
IMAGE_TAG=${2:-latest}
DOCKER_REPOSITORY=${3:-cilium}
DOCKER_REGISTRY=${4:-}


IMAGE_ARCH=("amd64" "arm64")

if [ -z "${IMAGE_NAME}" ]
then
  echo "Please specify a image name!"
  echo -e "\nUsage::\n\tpush_manifest.sh IMAGE_NAME [IMAGE_TAG] [DOCKER_REPOSITORY] [DOCKER_REGISTRY]"
  echo -e "\nExample::\n\tpush_manifest.sh cilium-runtime latest"
  exit 1
fi

export DOCKER_CLI_EXPERIMENTAL=enabled

for arch in "${IMAGE_ARCH[@]}"	
do
	docker push ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}-${arch}
done

docker manifest create --amend ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG} \
	${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}-amd64 \
	${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}-arm64

docker manifest push ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}

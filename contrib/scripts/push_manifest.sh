#!/usr/bin/env bash
set -e

IMAGE_NAME=${1:-}
IMAGE_TAG=${2:-latest}
DOCKER_REPOSITORY=${3:-cilium}
DOCKER_REGISTRY=${4:-}
IMAGE_ARCH=("amd64" "arm64")

function using_help() {
  echo "Please specify a image name!"
  echo -e "\nUsage::\n\tpush_manifest.sh IMAGE_NAME [IMAGE_TAG] [DOCKER_REPOSITORY] [DOCKER_REGISTRY]"
  echo -e "\nExample::\n\tpush_manifest.sh cilium-runtime latest"
  exit 1
}

function install_manifest() {
  MANIFEST_VERSION=v1.0.0
  rm -f ./manifest-tool
  wget https://github.com/estesp/manifest-tool/releases/download/${MANIFEST_VERSION}/manifest-tool-linux-${ARCH} \
          -O manifest-tool
  chmod +x ./manifest-tool
}

if [ -z "${IMAGE_NAME}" ]
then
  using_help
fi

# push images
for arch in "${IMAGE_ARCH[@]}"	
do
  ${CONTAINER_ENGINE} push ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}-${arch}
done

# get hardware name
case `uname -m` in
  'x86_64' )
    ARCH=amd64
    ;;
  'aarch64' )
    ARCH=arm64
    ;;
esac

# install manifest-tool v1.0.0
install_manifest

for arch in "${IMAGE_ARCH[@]}"
do
  if [ -z "$PLATFORMS" ]; then
    PLATFORMS="linux/${arch}"
  else
    PLATFORMS="$PLATFORMS,linux/${arch}"
  fi
done

./manifest-tool push from-args --platforms ${PLATFORMS} \
	--template ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}-ARCH \
	--target ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}/${IMAGE_NAME}:${IMAGE_TAG}

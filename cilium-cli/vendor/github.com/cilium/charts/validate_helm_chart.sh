#!/usr/bin/env bash
#
# Validate that the image tags in the Helm chart match the chart version.
#

set -e
shopt -s expand_aliases

DOCKER=${DOCKER:-docker}

helm() {
  "${DOCKER}" run --user "$(id -u):$(id -g)" --rm -v "$(pwd)":/apps alpine/helm:3.15.1 "$@"
}

yq () {
  "${DOCKER}" run -i --user "$(id -u):$(id -g)" --rm -v "${PWD}":/workdir mikefarah/yq:4.40.5 "$@"
}

usage() {
    >&2 echo "usage: $0 <chart-tgz-file>"
    >&2 echo
    >&2 echo "example: $0 cilium-1.15.5.tgz"
    >&2 echo "example: $0 tetragon-1.1.0.tgz"
}

CILIUM_IMAGE_PATHS=(
  '{$.clustermesh.apiserver.image.tag}'
  '{$.hubble.relay.image.tag}'
  '{$.image.tag}'
  '{$.operator.image.tag}'
  '{$.preflight.image.tag}'
)

TETRAGON_IMAGE_PATHS=(
  '{$.tetragon.image.tag}'
  '{$.tetragonOperator.image.tag}'
)

# $1 - Helm chart tgz file
main() {
  TGZ="$1"

  if [ ! -f "$TGZ" ]; then
      echo "ERROR: Chart tgz file not found: $TGZ"
      usage
      exit 1
  fi
  APP=$(helm show chart "$TGZ" | yq e '.name' -)
  CHART_VERSION=$(helm show chart "$TGZ" | yq e '.version' -)
  if [ "$APP" == "cilium" ]; then
    IMAGE_PATHS=("${CILIUM_IMAGE_PATHS[@]}")
  elif [ "$APP" == "tetragon" ]; then
    IMAGE_PATHS=("${TETRAGON_IMAGE_PATHS[@]}")
  else
    echo "Unsupported app $APP"
    exit 1
  fi

  for path in "${IMAGE_PATHS[@]}"; do
    tag=$(helm show values --jsonpath "$path" "$TGZ")
    if [ "$tag" == "v$CHART_VERSION" ]; then
      echo "SUCCESS: $APP $path=$tag matches chart version $CHART_VERSION"
    else
      echo "ERROR: $APP $path=$tag does not match chart version $CHART_VERSION"
      exit 1
    fi
  done
}

main "$@"

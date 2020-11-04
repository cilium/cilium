#!/usr/bin/env bash

cilium_tag="${1}"
org="cilium"

external_dependencies_docker=(
  "envoyproxy/envoy:${HUBBLE_PROXY_VERSION}" \
)

external_dependencies_quay=(
  "coreos/etcd:${ETCD_VERSION}" \
)

internal_dependencies=(
  "certgen:${CERTGEN_VERSION}" \
  "cilium-etcd-operator:${MANAGED_ETCD_VERSION}" \
  "startup-script:${NODEINIT_VERSION}"
  "hubble-ui:${HUBBLE_UI_VERSION}" \
  "hubble-ui-backend:${HUBBLE_UI_VERSION}" \
)

cilium_images=(\
  "cilium" \
  "clustermesh-apiserver" \
  "docker-plugin" \
  "hubble-relay" \
  "operator" \
  "operator-azure" \
  "operator-aws" \
  "operator-generic" \
)

docker_tag_exists(){
  local repo="${1}"
  local tag="${2}"
  curl --silent -f -lSL "https://index.docker.io/v1/repositories/${repo}/tags/${tag}" &> /dev/null
}

quay_tag_exists(){
  local repo="${1}"
  local tag="${2}"
  curl --silent -f -lSL "https://quay.io/api/v1/repository/${repo}/tag/${tag}/images" &> /dev/null
}

for image in "${external_dependencies_docker[@]}" ; do
  image_tag=${image#*:}
  image_name=${image%":$image_tag"}
  if ! docker_tag_exists "${image_name}" "${image_tag}" ; then
    echo "docker.io/${image} does not exist!"
    not_found=true
  fi
done

for image in "${external_dependencies_quay[@]}" ; do
  image_tag=${image#*:}
  image_name=${image%":$image_tag"}
  if ! quay_tag_exists "${image_name}" "${image_tag}" ; then
    echo "quay.io/${image} does not exist!"
    not_found=true
  fi
done

for image in "${internal_dependencies[@]}" ; do
  image_tag=${image#*:}
  image_name=${org}/${image%":$image_tag"}
  if ! docker_tag_exists "${image_name}" "${image_tag}" ; then
    echo "docker.io/${image_name}:${image_tag} does not exist!"
    not_found=true
  fi
  if ! quay_tag_exists "${image_name}" "${image_tag}" ; then
    echo "quay.io/${image_name}:${image_tag} does not exist!"
    not_found=true
  fi
done

for image in "${cilium_images[@]}"; do
  image_name="${org}/${image}"
  if ! docker_tag_exists "${image_name}" "${cilium_tag}" ; then
    echo "docker.io/${image_name}:${cilium_tag} does not exist!"
    not_found=true
  fi
  if ! quay_tag_exists "${image_name}" "${cilium_tag}" ; then
    echo "quay.io/${image_name}:${cilium_tag} does not exist!"
    not_found=true
  fi
done

if [[ -n "${not_found}" ]]; then
  exit 1
fi

exit 0

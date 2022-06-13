#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

cilium_tag="${1}"
org="cilium"
suffix=${CILIUM_OPERATOR_SUFFIX:-}

external_dependencies=(
  "quay.io/coreos/etcd:${ETCD_VERSION}" \
)

internal_dependencies_quay_only=(
  "cilium-etcd-operator:${CILIUM_ETCD_OPERATOR_VERSION}" \
  "startup-script:${CILIUM_NODEINIT_VERSION}"
)

internal_dependencies=(
  "certgen:${CERTGEN_VERSION}" \
  "hubble-ui:${HUBBLE_UI_FRONTEND_VERSION}" \
  "hubble-ui-backend:${HUBBLE_UI_BACKEND_VERSION}" \
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

image_tag_exists(){
  local image="${1}"
  docker buildx imagetools inspect "${image}" &> /dev/null
}

for image in "${external_dependencies[@]}" ; do
  if ! image_tag_exists "${image}" ; then
    echo "${image} does not exist!"
    not_found=true
  fi
done

for image in "${internal_dependencies[@]}" ; do
  image_tag=${image#*:}
  image_name=${org}/${image%":$image_tag"}
  if ! image_tag_exists "docker.io/${image_name}:${image_tag}" ; then
    echo "docker.io/${image_name}:${image_tag} does not exist!"
    not_found=true
  fi
done

for image in "${internal_dependencies[@]}" "${internal_dependencies_quay_only[@]}" ; do
  image_tag=${image#*:}
  image_name=${org}/${image%":$image_tag"}
  if ! image_tag_exists "quay.io/${image_name}:${image_tag}" ; then
    echo "quay.io/${image_name}:${image_tag} does not exist!"
    not_found=true
  fi
done

for image in "${cilium_images[@]}"; do
  image_name="${org}/${image}"
  if [ -z "${suffix}" ] && ! image_tag_exists "docker.io/${image_name}:${cilium_tag}" ; then
    echo "docker.io/${image_name}:${cilium_tag} does not exist!"
    not_found=true
  fi
  if ! image_tag_exists "quay.io/${image_name}${suffix}:${cilium_tag}" ; then
    echo "quay.io/${image_name}${suffix}:${cilium_tag} does not exist!"
    not_found=true
  fi
done

if [[ -n "${not_found}" ]]; then
  exit 1
fi

exit 0

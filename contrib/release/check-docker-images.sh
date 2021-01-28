#!/usr/bin/env bash

cilium_tag="${1}"
org="cilium"

external_dependencies_docker=(
)

external_dependencies_quay=(
)

external_dependencies_gcr=(
  "google-containers/startup-script:${NODEINIT_VERSION}"
)

internal_dependencies=(
  "cilium-etcd-operator:${MANAGED_ETCD_VERSION}" \
)

cilium_images=(\
  "cilium" \
  "docker-plugin" \
  "operator" \
)

docker_tag_exists(){
  local repo="${1}"
  local tag="${2}"
  curl --silent -f -lSL "https://index.docker.io/v1/repositories/${repo}/tags/${tag}" &> /dev/null
}

gcr_tag_exists(){
  local repo="${1}"
  local tag="${2}"
  curl --silent -f -lSL "https://gcr.io/api/v1/repository/${repo}/tag/${tag}/images" &> /dev/null
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

for image in "${external_dependencies_gcr[@]}" ; do
  image_tag=${image#*:}
  image_name=${image%":$image_tag"}
  if ! gcr_tag_exists "${image_name}" "${image_tag}" ; then
    echo "gcr.io/${image} does not exist!"
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

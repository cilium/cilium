#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
dst_file="${dir}/concepts/kubernetes/compatibility-table.rst"

. "${dir}/../contrib/backporting/common.sh"
remote="$(get_remote)"

set -o nounset
set -o pipefail

# Ensure sort order doesn't depend on locale
export LANG=C
export LC_ALL=C

get_schema_of_tag(){
   tag="${1}"
   git grep -o 'CustomResourceDefinitionSchemaVersion =.*' ${tag} -- pkg/k8s | head -n1 | sed 's/.*=\ "//;s/"//'
}

get_line_of_schema_version(){
   tag="${1}"
   git grep -H 'CustomResourceDefinitionSchemaVersion =.*' ${remote}/${tag} -- pkg/k8s | sed "s+${remote}/${tag}:++;s+.go:.*+.go+"
}

get_schema_of_branch(){
   stable_branch="${1}"
   git grep -o 'CustomResourceDefinitionSchemaVersion =.*' ${remote}/${stable_branch} -- pkg/k8s | sed 's/.*=\ "//;s/"//' | uniq
}

get_stable_branches(){
   git grep -o -E 'tree\/v[^>]+' -- README.rst | sed 's+.*tree/++' | sort -V
}

get_stable_tags_for_minor(){
   minor_ver="${1}"
   git ls-remote --refs --tags ${remote} v\* \
       | awk '{ print $2 }' \
       | grep "${minor_ver}" \
       | grep -v '\-' \
       | sed 's+refs/tags/++' \
       | sort -V \
   || echo ""
}

get_rc_tags_for_minor(){
   minor_ver="${1}"
   git ls-remote --refs --tags ${remote} v\* \
       | awk '{ print $2 }' \
       | grep "${minor_ver}.*\-" \
       | sed 's+refs/tags/++' \
       | sort -V
}

filter_out_oldest() {
    echo "${@}" | cut -d' ' -f2- -
}

create_file(){
  release_version="${1}"
  dst_file="${2}"
  git fetch --tags
  echo   "+-----------------+----------------+" > "${dst_file}"
  echo   "| Cilium          | CNP and CCNP   |" >> "${dst_file}"
  echo   "| Version         | Schema Version |" >> "${dst_file}"
  echo   "+-----------------+----------------+" >> "${dst_file}"
  stable_branches=$(get_stable_branches)
  if [[ ${stable_branches} != *"${release_version}"* ]]; then
      stable_branches="$(filter_out_oldest ${stable_branches} ${release_version})"
  fi
  for stable_branch in ${stable_branches}; do
      >&2 echo -n "Checking stable branch ${stable_branch} schema version... "
      rc_tags=$(get_rc_tags_for_minor "${stable_branch}")
      stable_tags=$(get_stable_tags_for_minor "${stable_branch}")
      for tag in ${rc_tags} ${stable_tags}; do
          schema_version=$(get_schema_of_tag "${tag}")
          printf "| %-15s | %-14s |\n" ${tag} ${schema_version} >> "${dst_file}"
          echo   "+-----------------+----------------+" >> "${dst_file}"
      done
      schema_version=$(get_schema_of_branch "${stable_branch}")
      >&2 echo "${schema_version}"
      printf "| %-15s | %-14s |\n" ${stable_branch} ${schema_version} >> "${dst_file}"
      echo   "+-----------------+----------------+" >> "${dst_file}"
  done

  schema_version=$(get_schema_of_branch "master")
  >&2 echo "Checking latest branch schema version... ${schema_version}"
  printf "| %-15s | %-14s |\n" "latest / master" ${schema_version} >> "${dst_file}"
  echo   "+-----------------+----------------+" >> "${dst_file}"
}

# From https://github.com/cloudflare/semver_bash/blob/master/semver.sh
semverParseInto() {
    local RE='[^0-9]*\([0-9]*\)[.]\([0-9]*\)[.]\([0-9]*\)\([0-9A-Za-z-]*\)'
    #MAJOR
    eval $2=`echo $1 | sed -e "s#$RE#\1#"`
    #MINOR
    eval $3=`echo $1 | sed -e "s#$RE#\2#"`
    #MINOR
    eval $4=`echo $1 | sed -e "s#$RE#\3#"`
    #SPECIAL
    eval $5=`echo $1 | sed -e "s#$RE#\4#"`
}

# From https://github.com/cloudflare/semver_bash/blob/master/semver.sh
semverEQ() {
    local MAJOR_A=0
    local MINOR_A=0
    local PATCH_A=0
    local SPECIAL_A=0

    local MAJOR_B=0
    local MINOR_B=0
    local PATCH_B=0
    local SPECIAL_B=0

    semverParseInto $1 MAJOR_A MINOR_A PATCH_A SPECIAL_A
    semverParseInto $2 MAJOR_B MINOR_B PATCH_B SPECIAL_B

    if [ $MAJOR_A -ne $MAJOR_B ]; then
        return 4
    fi

    if [ $MINOR_A -ne $MINOR_B ]; then
        return 3
    fi

    if [ $PATCH_A -ne $PATCH_B ]; then
        return 2
    fi

    if [[ "_$SPECIAL_A" != "_$SPECIAL_B" ]]; then
        return 1
    fi


    return 0
}

if [[ "$#" -ne 1 ]]; then
  echo "Usage: $0 <v1.X>"
  exit 1
fi

release_ersion="$(echo $1 | sed 's/^v//')"
release_version="v$release_ersion"

create_file ${release_version} "${dst_file}"

last_cilium_release=$(egrep "[ ]${release_version}[ ]" -B2 "${dst_file}" | awk 'NR == 1 { print $2 }')
last_release_version=$(egrep "[ ]${release_version}[ ]" -B2 "${dst_file}" | awk 'NR == 1 { print $4 }')
current_release_version=$(egrep "[ ]${release_version}[ ]" "${dst_file}" | awk 'NR == 1 { print $4 }')
>&2 echo "Cilium ${last_cilium_release} schema: ${last_release_version}; Current: ${current_release_version}"

# Cilium v1.9 or earlier used examples/crds, this dir was moved in v1.10.
crd_path="$(realpath --relative-to . "examples/crds")"

if ! git diff --quiet ${last_cilium_release}..${remote}/${release_version} $crd_path \
    && semverEQ "${current_release_version}" "${last_release_version}"; then
  semverParseInto ${last_release_version} last_major last_minor last_patch ignore
  expected_version="${last_major}.${last_minor}.$(( ${last_patch} + 1 ))"
  if [[ "${current_release_version}" != "${expected_version}" ]]; then
    >&2 echo "Current version for branch ${release_version} should be ${expected_version}, not ${current_release_version}, please run the following command to fix it:"
    >&2 echo "git checkout ${remote}/${release_version} && \\"
    >&2 echo "sed -i 's+${current_release_version}+${expected_version}+' $(get_line_of_schema_version ${release_version})"
    exit 1
  fi
fi

exit 0

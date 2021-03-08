#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source "${DIR}/lib/common.sh"

CONTAINER_ENGINE=${CONTAINER_ENGINE:-docker}

repo="cilium/cilium"

usage() {
    logecho "usage: $0 <GH-USERNAME> <VERSION> <RUN-URL>"
    logecho "GH-USERNAME  GitHub username"
    logecho "VERSION      Target version"
    logecho "RUN-URL      GitHub URL with the RUN for the release images"
    logecho "             example: https://github.com/cilium/cilium/actions/runs/600920964"
    logecho "GITHUB_TOKEN environment variable set with the scope public:repo"
    logecho
    logecho "--help     Print this help message"
}

handle_args() {
    if ! common::argc_validate 4; then
        usage 2>&1
        common::exit 1
    fi

    if [[ "$1" = "--help" ]] || [[ "$1" = "-h" ]]; then
        usage
        common::exit 0
    fi

    if ! echo "$2" | grep -q "[0-9]\+\.[0-9]\+\.[0-9]\+"; then
        usage 2>&1
        common::exit 1 "Invalid VERSION ARG \"$2\"; Expected X.Y.Z"
    fi

    if [ -z "${GITHUB_TOKEN}" ]; then
        usage 2>&1
        common::exit 1 "GITHUB_TOKEN not set!"
    fi
}

get_digest_output() {
    local username run_id file tmp_dir archive_download_url archive_download_url_zip

    username="${1}"
    run_id="${2}"
    version="${3}"
    file="${4}"
    tmp_dir=$(mktemp -d)
    archive_download_url=$(curl -SslH "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/${repo}/actions/runs/${run_id}/artifacts" \
      2>/dev/null | jq -r ".artifacts[] | select(.name == \"${file}-${version}\") | .archive_download_url")
    archive_download_url_zip=$(curl -SslH "Accept: application/vnd.github.v3+json" \
      -i -u "${username}:${GITHUB_TOKEN}" \
      "${archive_download_url}" 2>/dev/null | tr -d '\r' | grep -E '^location:\.*' | sed 's/location:\ //g')
    curl -Ssl "${archive_download_url_zip}" > "${tmp_dir}/${file}.zip"
    unzip -p "${tmp_dir}/${file}.zip" "${file}" > "${tmp_dir}/${file}"
    echo "${tmp_dir}/${file}"
}

main() {
    handle_args "$@"
    local username version run_url_id
    username="${1}"
    version="${2}"
    run_url_id="$(basename "${3}")"

    makefile_digest=$(get_digest_output "${username}" "${run_url_id}" "${version}" Makefile.digests)
    >&2 echo "Adding image SHAs to install/kubernetes/Makefile.digests"
    >&2 echo ""
    cp "${makefile_digest}" "${DIR}/../../install/kubernetes/Makefile.digests"

    >&2 echo "Generating manifest text for release notes"
    >&2 echo ""
    echo "Docker Manifests" > "${DIR}/../../digest-${version}.txt"
    echo "----------------" >> "${DIR}/../../digest-${version}.txt"
    image_digest_output=$(get_digest_output "${username}" "${run_url_id}" "${version}" image-digest-output.txt)
    cat "${image_digest_output}" >> "${DIR}/../../digest-${version}.txt"
    >&2 echo "Image digests available at ${DIR}/../../digest-${version}.txt"
}

main "$@"


#!/usr/bin/env bash

set -eux
shopt -s expand_aliases

DOCKER=${DOCKER:-docker}
ORG=${ORG:-cilium}

cosign() {
  "${DOCKER}" run --rm ghcr.io/sigstore/cosign/cosign:v3.0.2 "$@"
}

helm() {
  "${DOCKER}" run --user "$(id -u):$(id -g)" --rm -v "$(pwd)":/apps alpine/helm:3.12.0 "$@"
}

jq () {
  "${DOCKER}" run --rm -i ghcr.io/jqlang/jq:1.7.1 "$@"
}

usage() {
    >&2 echo "usage: $0 <project> <version>"
    >&2 echo
    >&2 echo "example: $0 cilium v1.15.0"
    >&2 echo "example: $0 tetragon v1.2.0"
}

# $1 - target ref
# $2 - remote
symbolic_ref() {
    local target="$1"
    local remote="$2"

    git symbolic-ref "$target" | sed 's@^refs/remotes/'"$remote"'/@@'
}

# $1 - project
# $2 - version
main() {
    PROJECT="$1"
    version="$2"
    ersion="$(echo $version | sed -e 's/^v//')"

    if [ "$PROJECT" != cilium  ] && [ "$PROJECT" != "tetragon" ] ; then
        echo "bad project $PROJECT"
        usage
        exit 1
    fi

    if echo "$ersion" | grep "^[0-9]+\.[0-9]+\.[0-9]+[0-9a-zA-Z_.-]*$" ; then
        echo "bad version '$version'"
        usage
        exit 1
    fi

    remote=$(git remote -v | grep "${ORG}/charts" | awk '{print $1;exit}')
    default_branch=$(symbolic_ref "refs/remotes/${remote}/HEAD" "${remote}")
    if [ "$(symbolic_ref HEAD "${remote}")" !=  "${default_branch}" ]; then
        git stash
        git checkout $default_branch
        git fetch "${remote}"
        git merge --ff-only "${remote}/${default_branch}"
    fi

    CWD=$(git rev-parse --show-toplevel)
    chart_dir="${PROJECT}/install/kubernetes"
    if [ -d "${PROJECT}" ]; then
        cd "${PROJECT}"
        git stash
        remote=$(git remote -v | grep "${ORG}/${PROJECT}" | awk '{print $1;exit}')
        git fetch "${remote}"
        git checkout "$version"
        cd -
    else
        git clone --depth 1 --branch "$version" "https://github.com/cilium/${PROJECT}.git"
    fi
    cd "${chart_dir}" || exit

    ## Cilium generate helm from templates (digest substitution)
    if [ "${PROJECT}" == "cilium" ]; then
        grep export < Makefile.digests | while IFS= read -r line; do
          variable_name=$(echo "$line" | cut -d ' ' -f 2)
          image=$(echo "$variable_name" | sed -e "s/_DIGEST$//" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
          digest=$(cosign verify --certificate-github-workflow-repository "cilium/${PROJECT}" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            --certificate-github-workflow-name "Image Release Build" \
            --certificate-github-workflow-ref "refs/tags/${version}" \
            --certificate-identity "https://github.com/cilium/${PROJECT}/.github/workflows/build-images-releases.yaml@refs/tags/${version}" \
            "quay.io/cilium/${image}:${version}" 2>/dev/null | \
            jq -r '.[].critical
              | select(.type == "https://sigstore.dev/cosign/sign/v1" or .type == "cosign container image signature")
              | .image["docker-manifest-digest"]')
          echo "export $variable_name := $digest" >> Makefile.digests.tmp
        done

        mv Makefile.digests.tmp Makefile.digests

        # TODO i don't want to have to specify CILIUM_BRANCH. struggle.
        make RELEASE=yes CILIUM_BRANCH=main CILIUM_VERSION="${version}"

        >&2 echo "Debugging the diff in cilium tree"
        git --no-pager diff
    fi

    helm package "${PROJECT}"
    cd -
    helm repo index --merge index.yaml "${PROJECT}/install/kubernetes"
    mv "${chart_dir}/${PROJECT}-${ersion}".tgz "${chart_dir}/index.yaml" "${CWD}"
    ./generate_readme.sh > README.md
    git add README.md index.yaml "${PROJECT}-${ersion}".tgz
    git commit -s -m "Add ${PROJECT} $version@$(cd ${PROJECT}; git rev-parse HEAD) ⎈"
}

main "$@"

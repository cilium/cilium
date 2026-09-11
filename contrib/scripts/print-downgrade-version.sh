#!/usr/bin/env bash
#
# A utility script to print the branch name of the previous stable or patch
# release.
#
# The script returns the estimated branch or tag name for the version to
# downgrade to. If it cannot determine this value, it returns nothing (and
# prints a message to stderr). It belongs to the calling workflow to determine
# whether an empty value should lead to an error or to skipping parts of a CI
# job.
#
# To some extent, this script is taylored for Cilium's CI workflows, and is
# probably not something you want to run for other purposes.
#
# Usage:
#
#   $ print-downgrade-version.sh <stable|patch>
#
# With "stable", the script prints the branch name of the previous stable
# branch. With "patch", it attempts to find out the tag of the latest patch
# release for the current branch.
#
# The version for the previous branch is computed by decrementing the minor
# version number for the current branch, based on the value in VERSION.
#
# The version for the latest patch release is computed as follows:
#
# - Error out on the development branch (if the VERSION ends with "-dev").
# - If the value in VERSION corresponds to an existing tag, return this value.
# - If the value in VERSION does not correspond to an existing tag, assume we
#   are on a release preparation Pull Request and attempt to compute the
#   previous patch release by decrementing the patch release version.
#
# Environment variables:
#
# - VERSION: The version supposed to be in the VERSION file at the root of the
#   repository. For testing purposes.
# - BRANCH_SUFFIX: A suffix to append to the generated branch name, when
#   downgrading to the lower stable branch.
# - TAG_SUFFIX: A suffix to append to the generated tag name, when downgrading
#   to the latest patch release, provided the script does not simply reuse the
#   value in VERSION.

set -o errexit
set -o nounset

usage() {
    >&2 echo "Usage: $0 <stable|patch>"
    exit 1
}

if [[ "$#" -ne 1 ]]; then
    usage
fi
case "${1}" in
    stable|patch)
        ;;
    *)
        usage
        ;;
esac

REMOTE_ORIGIN="${REMOTE_ORIGIN:-origin}"

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VERSION="${VERSION-"$(cat "${SCRIPT_DIR}/../../VERSION")"}"
if [[ "${VERSION}" =~ ([0-9^]+)\.([0-9^]+)\.([0-9^]+).* ]] ; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
else
  >&2 echo "ERROR: failed to parse version '${VERSION}'"
  exit 1
fi

tag_exists() {
    local tag="${1}"

    # Check if the tag is already present locally.
    if git rev-parse --verify --end-of-options "refs/tags/${tag}" &> /dev/null; then
        return 0
    fi

    # If not, check whether the tag exists on the remote. We no longer assume
    # tags have been pre-fetched (e.g. shallow clones in CI won't have them),
    # so ls-remote is the source of truth for tag existence.
    #
    # Note: Stuff we tried before in the past (for the patch release case),
    # instead of querying the remote in this script:
    #
    # - Downloading the tags directly in the CI workflow YAML file, by passing
    #   "fetch-tags: true" to the checkout Action. This does not work with
    #   shallow clones, only the tags pointing to objects present in the clone
    #   are fetched.
    # - Setting "fetch-depth: 2" in the workflow to fetch two commits: the
    #   latest commit on top of a commit that squashes all the rest of the
    #   history. Then we can check whether the latest commit updates VERSION,
    #   and assume we're on a release preparation PR in that case. This does
    #   not work well, however, if the release manager pushes additional fixes
    #   on top of the prep commit.
    >&2 echo "INFO: tag '${tag}' not present locally, checking remote '${REMOTE_ORIGIN}'"
    if git ls-remote --tags --exit-code "${REMOTE_ORIGIN}" "refs/tags/${tag}" &> /dev/null; then
        return 0
    fi

    return 1
}

find_previous_tag_for_version() {
    local version="${1}" major minor
    local tag_suffix="${TAG_SUFFIX:-}"

    if [[ ! "${version}" =~ ^([0-9]+)\.([0-9]+)\. ]] ; then
        >&2 echo "ERROR: failed to parse version '${version}'"
        return 1
    fi

    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"

    # Query the remote directly — tags are not assumed to be pre-fetched.
    mapfile -t candidate_tags < <(
        git ls-remote --tags --refs "${REMOTE_ORIGIN}" 'refs/tags/v*' \
            | awk '{print $NF}' \
            | sed 's|refs/tags/||' \
            | sort -rV
    )
    for tag in "${candidate_tags[@]}"; do
        local tag_version="${tag#v}"
        # parse version into major, minor, patch, optional suffix (e.g. -cee.N)
        if [[ "${tag_version}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-.+)?$ ]] ; then
            local t_major="${BASH_REMATCH[1]}"
            local t_minor="${BASH_REMATCH[2]}"
            local t_patch="${BASH_REMATCH[3]}"
            local t_suffix="${BASH_REMATCH[4]:-}"

            # Only consider tags matching the expected suffix family:
            #   - OSS build (no TAG_SUFFIX): accept only tags with no suffix.
            #   - Enterprise build (TAG_SUFFIX like "-cee.N"): accept ANY
            #     "-cee.*" tag, not just the exact TAG_SUFFIX, so downgrades
            #     across rebuild numbers (e.g. -cee.1 → -cee.2) still work.
            #   - Other suffix families: require an exact match.
            if [[ -z "${tag_suffix}" ]]; then
                [[ -z "${t_suffix}" ]] || continue
            elif [[ "${tag_suffix}" == -cee.* ]]; then
                [[ "${t_suffix}" == -cee.* ]] || continue
            else
                [[ "${t_suffix}" == "${tag_suffix}" ]] || continue
            fi

            # Check if this tag is older than the given version.
            if [[ "${t_major}" -lt "${major}" ]] || \
               [[ "${t_major}" -eq "${major}" && "${t_minor}" -lt "${minor}" ]] || \
               [[ "${t_major}" -eq "${major}" && "${t_minor}" -eq "${minor}" && "${t_patch}" -lt "${PATCH}" ]] ; then
                echo "${tag}"
                return 0
            fi
        fi
    done

    >&2 echo "ERROR: failed to find tag older than version '${version}'"
    return 1
}

print_prev_patch() {
    local version="${1}" major="${2}" minor="${3}" patch="${4}"
    local previous_tag

    # If we're on the development branch, there is no previous patch release to
    # downgrade to. Calling workflow should typically skip the job.
    if [[ "${version}" =~ -dev$ ]] ; then
        >&2 echo "ERROR: no previous patch release for development version '${version}'"
        exit 1
    fi

    # In most cases, the previous patch release is in fact the same as
    # indicated in $version and we just need to return it.
    # Note that we still prefix it with "v" to match the tag format.
    # Also note that in this case, we assume that VERSION already contains any
    # TAG_SUFFIX that would be required, and we do not append the content from
    # the environment variable.
    local tag="v${VERSION}"

    # Hack: When working on a patch release preparation PR, file VERSION
    # contains the new value for the release that is yet to be tagged and
    # published. So if the tag does not exist, we want to downgrade to the
    # previous patch release, by looking up the newest older tag on the remote.
    #
    # Only run this step if we're in a Git repository with the expected remote
    # configured.
    if git rev-parse --is-inside-work-tree &> /dev/null && \
        git remote | grep -q "^${REMOTE_ORIGIN}$" ; then

        if ! tag_exists "${tag}"; then
            # If the patch version is 0, we cannot decrement it further.
            if [[ "${patch}" -le "0" ]] ; then
                >&2 echo "ERROR: failed to deduce patch release previous to version '${version}' (cannot decrement patch version)"
                exit 1
            fi

            >&2 echo "INFO: tag '${tag}' not found. Querying remote '${REMOTE_ORIGIN}' for previous patch version."

            if previous_tag=$(find_previous_tag_for_version "${version}") ; then
                tag="${previous_tag}"
            else
                >&2 echo "ERROR: failed to deduce patch release previous to version '${version}' (no older tag found)"
                exit 1
            fi
        fi
    fi

    echo "${tag}"
}

print_prev_branch() {
    local version="${1}" major="${2}" minor="${3}"
    local branch_suffix="${BRANCH_SUFFIX:-}"

    # If the minor version is 0, we cannot decrement it further.
    if [[ "${minor}" == "0" ]] ; then
        >&2 echo "ERROR: failed to deduce release previous to version '${version}' (cannot decrement minor version number)"
        exit 1
    fi

    # Query the remote directly — stable branches are not assumed to be
    # present in a shallow clone. Loop through them to find the newest branch
    # older than the current version.
    while read -r ref ; do
        local branch="${ref#refs/heads/}"
        if [[ "${branch}" =~ ^v([0-9]+)\.([0-9]+)${branch_suffix}$ ]] ; then
            local b_major="${BASH_REMATCH[1]}"
            local b_minor="${BASH_REMATCH[2]}"

            if [[ "${b_major}" -lt "${major}" ]] || \
               [[ "${b_major}" -eq "${major}" && "${b_minor}" -lt "${minor}" ]] ; then
                echo "${branch}"
                return 0
            fi
        fi
    done < <(git ls-remote --heads "${REMOTE_ORIGIN}" 'refs/heads/v*' | awk '{print $NF}' | sort -rV)

    >&2 echo "ERROR: failed to find branch older than version '${version}'"
    exit 1
}

# If user passed "patch" as first argument, print the latest patch version.
# Otherwise, print the latest stable version.
if [[ ${1} == "patch" ]] ; then
    print_prev_patch "${VERSION}" "${MAJOR}" "${MINOR}" "${PATCH}"
else
    print_prev_branch "${VERSION}" "${MAJOR}" "${MINOR}"
fi

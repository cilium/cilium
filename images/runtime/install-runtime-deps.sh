#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

packages=(
  # Bash completion for Cilium
  bash-completion
  # Additional misc runtime dependencies
  iproute2
  iptables
  ipset
  kmod
  ca-certificates
  libatomic1
  jq
)

# Packages to be removed
purge_packages=(
  apt
  libapt-pkg7.0
)

export DEBIAN_FRONTEND=noninteractive

apt-get update

# tzdata is one of the dependencies and a timezone must be set
# to avoid interactive prompt when it is being installed
ln -fs /usr/share/zoneinfo/UTC /etc/localtime

# Update ubuntu packages to the most recent versions. Bump FORCE_BUILD in the
# Dockerfile to force this to re-run for stale images.
apt-get upgrade -y

apt-get install -y --no-install-recommends "${packages[@]}"

apt-get purge --auto-remove
apt-get clean

# Ensure the packages to be removed are actually present, this allows catching
# package name/version changes upon base ubuntu LTS upgrades
for package in "${purge_packages[@]}"; do
  if [[ "$(dpkg-query -f '${db:Status-Status}' -W "${package}" 2>/dev/null)" != "installed" ]]; then
    echo "Package ${package} is not installed, purge_packages needs updating" >&2
    exit 1
  fi
done

# Purge packages to be removed.
# Note: as the apt package manager is being removed here, any step relying on
# apt should be above this line in this file or in an earlier layer in the
# Dockerfile.
dpkg --purge "${purge_packages[@]}"

# Drop apt's leftover state directories.
rm -rf \
  /etc/apt \
  /var/lib/apt \
  /var/log/apt \
  /var/cache/apt

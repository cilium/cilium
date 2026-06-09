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

# The apt stack, followed by the libraries that become orphaned once apt is
# removed (the GnuTLS chain and its private dependencies). apt is the only
# package depending on GnuTLS, so purging apt lets us drop the entire GnuTLS
# stack, leaving OpenSSL as the single TLS implementation in the image.
# Deliberately does not include libgcrypt20 (needed by libsystemd0) or
# libgmp10 (needed by coreutils).
# This list of apt dependencies corresponds to the ubuntu 24.04 package graph,
# it will need to be updated on base ubuntu image upgrades.
purge_packages=(
  # Package manager.
  apt
  libapt-pkg6.0t64
  # GnuTLS and its crypto backends, orphaned once apt is gone.
  libgnutls30t64
  libhogweed6t64
  libnettle8t64
  # GnuTLS private dependencies, orphaned with it.
  libp11-kit0
  libtasn1-6
  libidn2-0
  libunistring5
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

# Purge the apt package manager and the libraries it is the sole consumer of.
# This is the last apt-based step: once apt is gone, no further apt-get steps can
# run, either here or downstream. dpkg is intentionally kept.
#
# Plain `dpkg --purge` (no --force-depends): if a future base image makes any of
# these libraries load-bearing for another package, the build will fails loudly
# here instead of silently shipping a broken image.
dpkg --purge "${purge_packages[@]}"

# Drop apt's leftover state directories.
rm -rf \
  /etc/apt \
  /var/lib/apt \
  /var/log/apt \
  /var/cache/apt

#!/bin/bash

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

cd /tmp

glibc_version="2.32-r0"

wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub
wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${glibc_version}/glibc-${glibc_version}.apk
apk add glibc-${glibc_version}.apk

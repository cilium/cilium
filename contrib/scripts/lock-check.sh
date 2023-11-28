#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Used to cause failure when pkg/lock is not used
for l in sync.Mutex sync.RWMutex; do
  if grep -r --exclude-dir={.git,_build,vendor,externalversions,lock,contrib} -i --include \*.go "$l" .; then
    echo "Found $l usage. Please use pkg/lock instead to improve deadlock detection";
    exit 1
  fi
done

if grep -r --exclude-dir={.git,_build,vendor,externalversions,lock,contrib} -i --include \*.go "sync.Map" .; then
  echo "Found sync.Map usages. Please use the generic pkg/lock.Map wrapper instead";
  exit 1
fi

#!/bin/bash
#
# Copyright 2017 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Used to cause failure when pkg/lock is not used
for l in sync.Mutex sync.RWMutex; do
  if grep -r --exclude-dir={.git,_build,vendor,externalversions,lock,contrib} -i --include \*.go "$l" .; then
    echo "Found $l usage. Please use pkg/lock instead to improve deadlock detection";
    exit 1
  fi
done

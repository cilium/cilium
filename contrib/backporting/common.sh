#!/bin/bash
#
# Copyright 2019 Authors of Cilium
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

set -e

get_remote () {
  local remote
  remote=$(git remote -v | \
    grep "github.com[/:]cilium/cilium" | \
    head -n1 | cut -f1)
  if [ -z "$remote" ]; then
      echo "No remote git@github.com:cilium/cilium.git or https://github.com/cilium/cilium found" 1>&2
      return 1
  fi
  echo "$remote"
}

require_linux() {
  if [ "$(uname)" != "Linux" ]; then
      echo "$0: Linux required"
      exit 1
  fi
}

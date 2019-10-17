#!/usr/bin/env bash

# Copyright 2019 The Kubernetes Authors.
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

# Explicitly opt into go modules, even though we're inside a GOPATH directory
export GO111MODULE=on
export GOFLAGS=
# Ensure sort order doesn't depend on locale
export LANG=C
export LC_ALL=C
TMP_DIR="${TMP_DIR:-$(mktemp -d /tmp/update-vendor.XXXX)}"

# ensure_require_replace_directives_for_all_dependencies:
# - ensures all existing 'require' directives have an associated 'replace' directive pinning a version
# - adds explicit 'require' directives for all transitive dependencies
# - adds explicit 'replace' directives for all require directives (existing 'replace' directives take precedence)
function ensure_require_replace_directives_for_all_dependencies() {
  local local_tmp_dir
  local_tmp_dir=$(mktemp -d "/tmp/pin_replace.XXXX")

  # collect 'require' directives that actually specify a version
  local require_filter='(.Version != null) and (.Version != "v0.0.0") and (.Version != "v0.0.0-00010101000000-000000000000")'
  # collect 'replace' directives that unconditionally pin versions (old=new@version)
  local replace_filter='(.Old.Version == null) and (.New.Version != null)'

  # Capture local require/replace directives before running any go commands that can modify the go.mod file
  local require_json="${local_tmp_dir}/require.json"
  local replace_json="${local_tmp_dir}/replace.json"
  go mod edit -json | jq -r ".Require // [] | sort | .[] | select(${require_filter})" > "${require_json}"
  go mod edit -json | jq -r ".Replace // [] | sort | .[] | select(${replace_filter})" > "${replace_json}"

  # 1a. Ensure replace directives have an explicit require directive
  jq -r '"-require \(.Old.Path)@\(.New.Version)"' < "${replace_json}" | xargs -L 100 go mod edit -fmt
  # 1b. Ensure require directives have a corresponding replace directive pinning a version
  jq -r '"-replace \(.Path)=\(.Path)@\(.Version)"' < "${require_json}" | xargs -L 100 go mod edit -fmt
  jq -r '"-replace \(.Old.Path)=\(.New.Path)@\(.New.Version)"' < "${replace_json}" | xargs -L 100 go mod edit -fmt

  # 3. Add explicit require directives for indirect dependencies
  go list -m -json all | jq -r 'select(.Main != true) | select(.Indirect == true) | "-require \(.Path)@\(.Version)"'          | xargs -L 100 go mod edit -fmt

  # 4. Add explicit replace directives pinning dependencies that aren't pinned yet
  go list -m -json all | jq -r 'select(.Main != true) | select(.Replace == null)  | "-replace \(.Path)=\(.Path)@\(.Version)"' | xargs -L 100 go mod edit -fmt
}

function group_replace_directives() {
  local local_tmp_dir
  local_tmp_dir=$(mktemp -d "/tmp/group_replace.XXXX")
  local go_mod_replace="${local_tmp_dir}/go.mod.replace.tmp"
  local go_mod_noreplace="${local_tmp_dir}/go.mod.noreplace.tmp"
  # separate replace and non-replace directives
  awk "
     # print lines between 'replace (' ... ')' lines
     /^replace [(]/      { inreplace=1; next                   }
     inreplace && /^[)]/ { inreplace=0; next                   }
     inreplace           { print > \"${go_mod_replace}\"; next }

     # print ungrouped replace directives with the replace directive trimmed
     /^replace [^(]/ { sub(/^replace /,\"\"); print > \"${go_mod_replace}\"; next }

     # otherwise print to the noreplace file
     { print > \"${go_mod_noreplace}\" }
  " < go.mod
  {
    cat "${go_mod_noreplace}";
    echo "replace (";
    cat "${go_mod_replace}";
    echo ")";
  } > go.mod

  go mod edit -fmt
}

function add_generated_comments() {
  local local_tmp_dir
  local_tmp_dir=$(mktemp -d "${TMP_DIR}/add_generated_comments.XXXX")
  local go_mod_nocomments="${local_tmp_dir}/go.mod.nocomments.tmp"

  # drop comments before the module directive
  cat go.mod | awk "
     BEGIN           { dropcomments=1 }
     /^module /      { dropcomments=0 }
     dropcomments && /^\/\// { next }
     { print }
  " > "${go_mod_nocomments}"

  # Add the specified comments
  local comments="${1}"
  echo "${comments}"         >  go.mod
  echo ""                    >> go.mod
  cat "${go_mod_nocomments}" >> go.mod

  # Format
  go mod edit -fmt
}


LOG_FILE="/tmp/log-file-mod"
# pin referenced versions
ensure_require_replace_directives_for_all_dependencies
# resolves/expands references in the root go.mod (if needed)
go mod tidy >>"${LOG_FILE}" 2>&1
# pin expanded versions
ensure_require_replace_directives_for_all_dependencies
# group replace directives
group_replace_directives

go mod tidy >>"${LOG_FILE}" 2>&1

add_generated_comments "
// This is a generated file. Do not edit directly.
// Run contrib/go-mod/pin-dependency.sh to change pinned dependency versions.
// Run contrib/go-mod/update-vendor.sh to update go.mod files and the vendor directory.
"
go mod vendor >>"${LOG_FILE}" 2>&1


TMP_DIR=/tmp
# sort recorded packages for a given vendored dependency in modules.txt.
# `go mod vendor` outputs in imported order, which means slight go changes (or different platforms) can result in a differently ordered modules.txt.
# scan                 | prefix comment lines with the module name       | sort field 1  | strip leading text on comment lines
cat vendor/modules.txt | awk '{if($1=="#") print $2 " " $0; else print}' | sort -k1,1 -s | sed 's/.*#/#/' > "${TMP_DIR}/modules.txt.tmp"
mv "${TMP_DIR}/modules.txt.tmp" vendor/modules.txt


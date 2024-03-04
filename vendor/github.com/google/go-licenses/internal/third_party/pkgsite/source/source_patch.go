// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package source

// This file includes all local additions to source package for google/go-licenses use-cases.

// SetCommit overrides commit to a specified commit. Usually, you should pass your version to
// ModuleInfo(). However, when you do not know the version and just wants a link that points to
// a known commit/branch/tag. You can use this method to directly override the commit like
// info.SetCommit("master").
//
// Note this is different from directly passing "master" as version to ModuleInfo(), because for
// modules not at the root of a repo, there are conventions that add a module's relative dir in
// front of the version as the actual git tag. For example, for a sub module at ./submod whose
// version is v1.0.1, the actual git tag should be submod/v1.0.1.
func (i *Info) SetCommit(commit string) {
	if i == nil {
		return
	}
	i.commit = commit
}

// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// +build darwin

package sysctl

// Disable disables the given sysctl parameter.
// On OS X and Darwin it's not doing anything. It just exists to make compilation
// possible.
func Disable(name string) error {
	return nil
}

// Enable enables the given sysctl parameter.
// On OS X and Darwin it's not doing anything. It just exists to make compilation
// possible.
func Enable(name string) error {
	return nil
}

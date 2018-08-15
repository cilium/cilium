// Copyright 2018 Authors of Cilium
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

package service

var (
	enableGlobalServiceIDs bool
)

// EnableGlobalServiceID enables or disables the use of global service IDs.
// When global service IDs are enabled, a kvstore interaction is used to
// allocate service IDs in the scope of the entire kvstore domain to enable
// transfer of service ID context between nodes.
func EnableGlobalServiceID(val bool) {
	enableGlobalServiceIDs = val
}

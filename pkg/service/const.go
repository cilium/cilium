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

const (
	// FirstFreeServiceID is the first ID for which the services should be assigned.
	FirstFreeServiceID = uint32(1)

	// MaxSetOfServiceID is maximum number of set of service IDs that can be stored
	// in the kvstore or the local ID allocator.
	MaxSetOfServiceID = uint32(0xFFFF)

	// FirstFreeBackendID is the first ID for which the backend should be assigned.
	// BPF datapath assumes that backend_id cannot be 0.
	FirstFreeBackendID = uint32(1)

	// MaxSetOfBackendID is maximum number of set of backendIDs IDs that can be
	// stored in the local ID allocator.
	MaxSetOfBackendID = uint32(0xFFFF)
)

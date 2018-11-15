// Copyright 2016-2018 Authors of Cilium
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

package endpoint

// ExternalRegenerationMetadata contains any information about a regeneration that
// the endpoint subsystem should be made aware of for a given endpoint.
type ExternalRegenerationMetadata struct {
	// Reason provides context to source for the regeneration, which is
	// used to generate useful log messages.
	Reason string

	// ReloadDatapath forces the datapath programs to be reloaded. It does
	// not guarantee recompilation of the programs.
	ReloadDatapath bool
}

func (e *ExternalRegenerationMetadata) toRegenerationContext() *regenerationContext {
	return &regenerationContext{
		Reason:         e.Reason,
		ReloadDatapath: e.ReloadDatapath,
	}
}

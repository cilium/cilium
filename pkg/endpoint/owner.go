// Copyright 2016-2017 Authors of Cilium
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

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {
	// Must return true if tracing of the policy resolution is to be enabled
	TracingEnabled() bool

	// Must return true if dry mode is enabled
	DryModeEnabled() bool

	// PolicyEnabled returns true if policy enforcement has been enabled
	PolicyEnabled() bool

	// Must return an instance of a ConsumableCache
	GetConsumableCache() *policy.ConsumableCache

	// Must resolve label id to an identiy
	GetCachedLabelList(ID policy.NumericIdentity) ([]labels.Label, error)

	// Must return the policy tree object
	GetPolicyTree() *policy.Tree

	// Return the next available global identity
	GetMaxLabelID() (policy.NumericIdentity, error)

	// Must return proxy object
	GetProxy() *proxy.Proxy

	// Must synchronize endpoint object with datapath
	WriteEndpoint(ep *Endpoint) error

	// Must return path to runtime directory
	GetRuntimeDir() string

	// Must return path to BPF template files directory
	GetBpfDir() string
}

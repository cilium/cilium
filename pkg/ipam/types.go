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

package ipam

import (
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/lock"

	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

// Config is the IPAM configuration used for a particular IPAM type.
type IPAM struct {
	nodeAddressing datapath.NodeAddressing
	config         Configuration

	IPv6Allocator *ipallocator.Range
	IPv4Allocator *ipallocator.Range

	// owner maps an IP to the owner
	owner map[string]string

	// mutex covers access to all members of this struct
	allocatorMutex lock.RWMutex

	blacklist map[string]string
}

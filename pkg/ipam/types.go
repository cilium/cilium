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
	"net"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/davecgh/go-spew/spew"
)

// Allocator is the interface for an IP allocator implementation
type Allocator interface {
	// Allocate allocates a specific IP or fails
	Allocate(ip net.IP, owner string) error

	// Release releases a previously allocated IP or fails
	Release(ip net.IP) error

	// AllocateNext allocates the next available IP or fails if no more IPs
	// are available
	AllocateNext(owner string) (net.IP, error)

	// Dump returns a map of all allocated IPs with the IP represented as
	// key in the map. Dump must also provide a status one-liner to
	// represent the overall status, e.g. number of IPs allocated and
	// overall health information if available.
	Dump() (map[string]string, string)
}

// Config is the IPAM configuration used for a particular IPAM type.
type IPAM struct {
	nodeAddressing datapath.NodeAddressing
	config         Configuration

	IPv6Allocator Allocator
	IPv4Allocator Allocator

	// owner maps an IP to the owner
	owner map[string]string

	// mutex covers access to all members of this struct
	allocatorMutex lock.RWMutex

	blacklist map[string]string
}

// DebugStatus implements debug.StatusObject to provide debug status collection
// ability
func (ipam *IPAM) DebugStatus() string {
	if ipam == nil {
		return "<nil>"
	}

	ipam.allocatorMutex.RLock()
	str := spew.Sdump(ipam)
	ipam.allocatorMutex.RUnlock()
	return str
}

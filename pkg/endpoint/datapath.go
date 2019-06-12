// Copyright 2016-2019 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/policy"
)

/*type EndpointDatapath interface {
	HasIpvlanDataPath() bool
	CloseBPFProgramChannel()
	HasBPFProgram()
	IPv4Address() addressing.CiliumIPv4
	IPv6Address() addressing.CiliumIPv6
	GetNodeMAC()
	PinDatapathMap() error
	BPFIpvlanMapPath() string
	BPFConfigMapPath() string
	CallsMapPathLocked() string
	PolicyMapPathLocked() string
	DeleteMapsLocked() string
	DeleteBPFProgramLocked() error
	garbageCollectConntrack(filter *ctmap.GCFilter)
	scrubIPsInConntrackTableLocked()
	GetBPFKeys() []*lxcmap.EndpointKey
	GetBPFValue() (*lxcmap.EndpointInfo, error)
}*/

// DatapathPolicy describes any type which allows for plumbing of policy into
// the datapath.
type DatapathPolicy interface {
	DeleteKey(policy.Key) error
	AllowKey(policy.Key, policy.MapStateEntry) error
	SyncDelta(realized policy.MapState, desired policy.MapState) error
	SyncFull(realized policy.MapState, desired policy.MapState) error
	Close() error
	DeleteAll() error
	OpenOrCreate(id uint16) (bool, error)
	String() string
	Path() string
	GetFd() int
	IsInit() bool
	AddID(id uint16)
	RemoveGlobalMapping(id uint32) error
}

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

package eppolicymap

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log          = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-ep-policy")
	MapName      = "cilium_ep_to_policy"
	innerMapName = "ep-policy-inner-map"
)

const (
	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65535
)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type EndpointKey struct{ bpf.EndpointKey }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type EPPolicyValue struct{ Fd uint32 }

var (
	buildMap sync.Once

	EpPolicyMap = bpf.NewMap(MapName,
		bpf.MapTypeHashOfMaps,
		&EndpointKey{},
		int(unsafe.Sizeof(EndpointKey{})),
		&EPPolicyValue{},
		int(unsafe.Sizeof(EPPolicyValue{})),
		MaxEntries,
		0,
		0,
		bpf.ConvertKeyValue,
	).WithCache()
)

// CreateEPPolicyMap will create both the innerMap (needed for map in map types) and
// then after BPFFS is mounted create the epPolicyMap. We only create the innerFd once
// to avoid having multiple inner maps.
func CreateEPPolicyMap() {
	buildMap.Do(func() {
		mapType := bpf.MapType(bpf.BPF_MAP_TYPE_HASH)
		fd, err := bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH,
			uint32(unsafe.Sizeof(policymap.PolicyKey{})),
			uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
			uint32(policymap.MaxEntries),
			bpf.GetPreAllocateMapFlags(mapType),
			0, innerMapName)

		if err != nil {
			log.WithError(err).Warning("unable to create EP to policy map")
			return
		}

		EpPolicyMap.InnerID = uint32(fd)
	})

	if _, err := EpPolicyMap.OpenOrCreate(); err != nil {
		log.WithError(err).Warning("Unable to open or create endpoint policy map")
	}
}

func (v EPPolicyValue) String() string { return fmt.Sprintf("fd=%d", v.Fd) }

// GetValuePtr returns the unsafe value pointer to the Endpoint Policy fd
func (v *EPPolicyValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// NewValue returns a new empty instance of the Endpoint Policy fd
func (k EndpointKey) NewValue() bpf.MapValue { return &EPPolicyValue{} }

// newEndpointKey return a new key from the IP address.
func newEndpointKey(ip net.IP) *EndpointKey {
	return &EndpointKey{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

func writeEndpoint(keys []*lxcmap.EndpointKey, fd int) error {
	if option.Config.SockopsEnable == false {
		return nil
	}

	if fd < 0 {
		return fmt.Errorf("WriteEndpoint invalid policy fd %d", fd)
	}

	/* Casting file desriptor into uint32 required by BPF syscall */
	epFd := &EPPolicyValue{Fd: uint32(fd)}

	for _, v := range keys {
		if err := EpPolicyMap.Update(v, epFd); err != nil {
			return err
		}
	}
	return nil
}

// WriteEndpoint writes the policy map file descriptor into the map so that
// the datapath side can do a lookup from EndpointKey->PolicyMap. Locking is
// handled in the usual way via Map lock. If sockops is disabled this will be
// a nop.
func WriteEndpoint(keys []*lxcmap.EndpointKey, pm *policymap.PolicyMap) error {
	return writeEndpoint(keys, pm.GetFd())
}

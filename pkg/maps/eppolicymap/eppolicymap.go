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

type endpointKey struct{ bpf.EndpointKey }
type epPolicyFd struct{ Fd uint32 }

var (
	buildMap sync.Once

	EpPolicyMap = bpf.NewMap(MapName,
		bpf.MapTypeHashOfMaps,
		int(unsafe.Sizeof(endpointKey{})),
		int(unsafe.Sizeof(epPolicyFd{})),
		MaxEntries,
		0,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k := endpointKey{}
			v := epPolicyFd{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}

			return &k, &v, nil
		},
	).WithCache()
)

// CreateEPPolicyMap will create both the innerMap (needed for map in map types) and
// then after BPFFS is mounted create the epPolicyMap. We only create the innerFd once
// to avoid having multiple inner maps.
func CreateEPPolicyMap() {
	buildMap.Do(func() {
		fd, err := bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH,
			uint32(unsafe.Sizeof(policymap.PolicyKey{})),
			uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
			policymap.MaxEntries,
			0, 0, innerMapName)

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

func (v epPolicyFd) String() string { return fmt.Sprintf("fd=%d", v.Fd) }

// GetValuePtr returns the unsafe value pointer to the Endpoint Policy fd
func (v epPolicyFd) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v.Fd) }

// NewValue returns a new empty instance of the Endpoint Policy fd
func (k endpointKey) NewValue() bpf.MapValue { return &epPolicyFd{} }

// newEndpointKey return a new key from the IP address.
func newEndpointKey(ip net.IP) *endpointKey {
	return &endpointKey{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

// WriteEndpoint writes the policy map file descriptor into the map so that
// the datapath side can do a lookup from endpointKey->PolicyMap. Locking is
// handled in the usual way via Map lock. If sockops is disabled this will be
// a nop.
func WriteEndpoint(keys []*lxcmap.EndpointKey, fd int) error {
	if option.Config.SockopsEnable == false {
		return nil
	}

	if fd < 0 {
		return fmt.Errorf("WriteEndpoint invalid policy fd %d", fd)
	}

	/* Casting file desriptor into uint32 required by BPF syscall */
	epFd := &epPolicyFd{Fd: uint32(fd)}

	for _, v := range keys {
		if err := EpPolicyMap.Update(v, epFd); err != nil {
			return err
		}
	}
	return nil
}

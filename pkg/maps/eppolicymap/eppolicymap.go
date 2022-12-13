// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eppolicymap

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	eppolicymapTypes "github.com/cilium/cilium/pkg/maps/eppolicymap/types"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log          = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-ep-policy")
	MapName      = "cilium_ep_to_policy"
	innerMapName = "ep_policy_inner_map"
)

const (
	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65536
)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapKey
type EndpointKey eppolicymapTypes.EndpointKey

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapValue
type EPPolicyValue eppolicymapTypes.EPPolicyValue

var (
	buildMap sync.Once

	// EpPolicyMap is the global singleton of the endpoint policy map.
	EpPolicyMap *bpf.Map
)

// CreateWithName creates a new endpoint policy hash of maps for
// looking up an endpoint's policy map by the endpoint key.
//
// The specified mapName allows non-standard map paths to be used, for instance
// for testing purposes.
func CreateWithName(mapName string) error {
	buildMap.Do(func() {
		mapType := bpf.MapTypeHash
		fd, err := bpf.CreateMap(mapType,
			uint32(unsafe.Sizeof(policymap.PolicyKey{})),
			uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
			uint32(policymap.MaxEntries),
			bpf.GetPreAllocateMapFlags(mapType),
			0, innerMapName)

		if err != nil {
			log.WithError(err).Fatal("unable to create EP to policy map")
			return
		}

		EpPolicyMap = bpf.NewMap(mapName,
			bpf.MapTypeHashOfMaps,
			&EndpointKey{},
			int(unsafe.Sizeof(EndpointKey{})),
			&EPPolicyValue{},
			int(unsafe.Sizeof(EPPolicyValue{})),
			MaxEntries,
			0,
			0,
			bpf.ConvertKeyValue,
		).WithCache().
			WithEvents(option.Config.GetEventBufferConfig(mapName))

		EpPolicyMap.InnerID = uint32(fd)
	})

	_, err := EpPolicyMap.OpenOrCreate()
	return err
}

// CreateEPPolicyMap will create both the innerMap (needed for map in map types) and
// then after BPFFS is mounted create the epPolicyMap. We only create the innerFd once
// to avoid having multiple inner maps.
func CreateEPPolicyMap() {
	if err := CreateWithName(MapName); err != nil {
		log.WithError(err).Warning("Unable to open or create endpoint policy map")
	}
}

func (v EPPolicyValue) String() string { return fmt.Sprintf("fd=%d", v.Fd) }

// GetValuePtr returns the unsafe value pointer to the Endpoint Policy fd
func (v *EPPolicyValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// NewValue returns a new empty instance of the Endpoint Policy fd
func (k EndpointKey) NewValue() bpfTypes.MapValue { return &EPPolicyValue{} }

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
func WriteEndpoint(f lxcmap.EndpointFrontend, pm *policymap.PolicyMap) error {
	keys := lxcmap.GetBPFKeys(f)
	return writeEndpoint(keys, pm.GetFd())
}

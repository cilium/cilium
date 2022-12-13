// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockmap

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	sockmapTypes "github.com/cilium/cilium/pkg/maps/sockmap/types"
)

// SockmapKey is the 5-tuple used to lookup a socket
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapKey
type SockmapKey sockmapTypes.SockmapKey

// SockmapValue is the fd of a socket
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapValue
type SockmapValue sockmapTypes.SockmapValue

// String pretty print the 5-tuple as sip:sport->dip:dport
func (v SockmapKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d", v.SIP.String(), v.SPort, v.DIP.String(), v.DPort)
}

// String pretty print the file descriptor value, note this is local to agent.
func (v SockmapValue) String() string {
	return fmt.Sprintf("%d", v.Fd)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *SockmapValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *SockmapKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k SockmapKey) NewValue() bpfTypes.MapValue { return &SockmapValue{} }

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "sockmap")

const (
	mapName = "cilium_sock_ops"

	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65535
)

var (
	buildMap sync.Once
	// SockMap represents the BPF map for sockets
	SockMap *bpf.Map
)

// CreateWithName creates a new sockmap map.
//
// The specified mapName allows non-standard map paths to be used, for instance
// for testing purposes.
func CreateWithName(name string) error {
	buildMap.Do(func() {
		SockMap = bpf.NewMap(name,
			bpf.MapTypeSockHash,
			&SockmapKey{},
			int(unsafe.Sizeof(SockmapKey{})),
			&SockmapValue{},
			4,
			MaxEntries,
			0, 0,
			bpf.ConvertKeyValue,
		)
	})

	_, err := SockMap.OpenOrCreate()
	return err
}

// SockmapCreate will create sockmap map
func SockmapCreate() {
	if err := CreateWithName(mapName); err != nil {
		log.WithError(err).Warning("Unable to open or create socket map")
	}
}

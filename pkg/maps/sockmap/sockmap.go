// Copyright 2018-2019 Authors of Cilium
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

package sockmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// SockmapKey is the 5-tuple used to lookup a socket
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SockmapKey struct {
	DIP    types.IPv6 `align:"$union0"`
	SIP    types.IPv6 `align:"$union1"`
	Family uint8      `align:"family"`
	Pad7   uint8      `align:"pad7"`
	Pad8   uint16     `align:"pad8"`
	SPort  uint32     `align:"sport"`
	DPort  uint32     `align:"dport"`
}

// SockmapValue is the fd of a socket
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type SockmapValue struct {
	fd uint32
}

// String pretty print the 5-tuple as sip:sport->dip:dport
func (v SockmapKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d", v.SIP.String(), v.SPort, v.DIP.String(), v.DPort)
}

// String pretty print the file descriptor value, note this is local to agent.
func (v SockmapValue) String() string {
	return fmt.Sprintf("%d", v.fd)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v SockmapValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k SockmapKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k SockmapKey) NewValue() bpf.MapValue { return &SockmapValue{} }

// NewSockmapKey returns a new key using 5-tuple input.
func NewSockmapKey(dip, sip net.IP, sport, dport uint32) SockmapKey {
	result := SockmapKey{}

	if sip4 := sip.To4(); sip4 != nil {
		result.Family = bpf.EndpointKeyIPv4
		copy(result.SIP[:], sip4)
	} else {
		result.Family = bpf.EndpointKeyIPv6
		copy(result.SIP[:], sip)
	}

	if dip4 := dip.To4(); dip4 != nil {
		result.Family = bpf.EndpointKeyIPv4
		copy(result.SIP[:], dip4)
	} else {
		result.Family = bpf.EndpointKeyIPv6
		copy(result.DIP[:], dip)
	}

	result.DPort = dport
	result.SPort = sport
	return result
}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "sockmap")

const (
	mapName = "cilium_sock_ops"

	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65535
)

var (
	// SockMap represents the BPF map for sockets
	SockMap = bpf.NewMap(mapName,
		bpf.MapTypeSockHash,
		&SockmapKey{},
		int(unsafe.Sizeof(SockmapKey{})),
		&SockmapValue{},
		4,
		MaxEntries,
		0, 0,
		bpf.ConvertKeyValue,
	)
)

// SockmapCreate will create sockmap map
func SockmapCreate() {
	SockMap.OpenOrCreate()
}

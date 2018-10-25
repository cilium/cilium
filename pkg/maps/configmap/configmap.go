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

package configmap

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-config")

const (
	// MapNamePrefix is the basename prefix of endpoint config maps.
	MapNamePrefix = "cilium_ep_config_"

	// MaxEntries represents the maximum number of elements in the map
	MaxEntries = 1

	// SkipPolicyIngress causes ingress policy to be skipped.
	SkipPolicyIngress = 1 << 0
	// SkipPolicyEgress causes ingress policy to be skipped.
	SkipPolicyEgress = 1 << 1
)

var (
	flagsToString = map[int]string{
		SkipPolicyIngress: "SKIP_POLICY_INGRESS",
		SkipPolicyEgress:  "SKIP_POLICY_EGRESS",
	}

	// configKey is the key in each endpoint's map for its configuration.
	configKey = Key{uint32: 0}
)

// Flags is a set of endpoint configuration flags interpreted by BPF code.
//
// Must be in sync with the enum ep_cfg_flag in <bpf/lib/eps.h>
type Flags uint32

// String converts the specified flags into a human-readable form.
func (f Flags) String() string {
	var buffer bytes.Buffer

	for i := uint(0); i < 32; i++ {
		bit := int(f & 1 << i)
		if bit > 0 {
			if flag, ok := flagsToString[bit]; ok {
				buffer.WriteString(flag)
				buffer.WriteString(",")
			} else {
				buffer.WriteString(fmt.Sprintf("Unknown(%#x)", bit))
			}
		}
	}

	return buffer.String()
}

// Key is the key used to index into the config map for an endpoint.
//
// Must be in sync with the key of CONFIG_MAP in <bpf/lib/maps.h>
type Key struct {
	uint32
}

// EndpointInfo represents the value of the endpoints BPF map.
//
// Must be in sync with struct config_value in <bpf/lib/common.h>
type EndpointConfig struct {
	Flags Flags
}

// GetValuePtr returns the unsafe pointer to the BPF value
func (c *EndpointConfig) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

// endpoint provides access to the properties of an endpoint that are relevant
// for configuring the BPF program for the endpoint.
type endpoint interface {
	GetIngressPolicyEnabledLocked() bool
	GetEgressPolicyEnabledLocked() bool
}

// EndpointConfigMap is a map type for interfacing with endpoint BPF config.
type EndpointConfigMap struct {
	path string
	Fd   int
}

// GetConfig creates a EndpointConfig structure using the endpoint's
// configuration.
func GetConfig(e endpoint) *EndpointConfig {
	value := EndpointConfig{}
	if !e.GetIngressPolicyEnabledLocked() {
		value.Flags &= SkipPolicyIngress
	}
	if !e.GetEgressPolicyEnabledLocked() {
		value.Flags &= SkipPolicyEgress
	}

	return &value
}

// Sync pushes the configuration options from the specified endpoint into the
// configuration map.
func (m *EndpointConfigMap) Update(value *EndpointConfig) error {
	return bpf.UpdateElement(m.Fd, unsafe.Pointer(&configKey),
		unsafe.Pointer(&value), 0)
}

// OpenMap attempts to open or create a BPF config map at the specified path.
// On success, it returns a map and whether the map was newly created, or
// otherwise an error.
func OpenMap(path string) (*EndpointConfigMap, bool, error) {
	fd, isNewMap, err := bpf.OpenOrCreateMap(
		path,
		bpf.BPF_MAP_TYPE_ARRAY,
		uint32(unsafe.Sizeof(uint32(0))),
		uint32(unsafe.Sizeof(EndpointConfig{})),
		MaxEntries,
		0,
	)

	if err != nil {
		return nil, false, err
	}

	m := &EndpointConfigMap{path: path, Fd: fd}

	return m, isNewMap, nil
}

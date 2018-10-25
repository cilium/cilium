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
	MaxEntries = 2

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

	binMap = map[uint]string{
		0: "POLICY_INGRESS",
		1: "POLICY_EGRESS",
	}

	// configKey is the key in each endpoint's map for its configuration.
	configKey = Key{Bits: 0}
)

// Flags is a set of endpoint configuration flags interpreted by BPF code.
//
// Must be in sync with the enum ep_cfg_flag in <bpf/lib/eps.h>
type Flags uint32

// String converts the specified flags into a human-readable form.
func (f Flags) String() string {
	var buffer bytes.Buffer
	for i := uint(0); i < 32; i++ {
		bitVal := int(f & (1 << i))
		if bitVal > 0 {
			if flag, ok := flagsToString[bitVal]; ok {
				buffer.WriteString(flag)
				buffer.WriteString(",")
			}
		} else if bitVal == 0 {
			if flag, ok := binMap[i]; ok {
				buffer.WriteString(flag)
				buffer.WriteString(",")
			}
		}
	}

	return buffer.String()
}

// Key is the key used to index into the config map for an endpoint.
//
// Must be in sync with the key of CONFIG_MAP in <bpf/lib/maps.h>
type Key struct {
	Bits uint32
}

func (k Key) String() string {
	return fmt.Sprintf("%d", k)
}

func (k Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k Key) NewValue() bpf.MapValue { return &EndpointConfig{} }

func (cfg EndpointConfig) String() string {
	return cfg.Flags.String()
}

// EndpointConfig represents the value of the endpoints BPF map.
//
// Must be in sync with struct config_value in <bpf/lib/common.h>
type EndpointConfig struct {
	Flags Flags
}

// GetValuePtr returns the unsafe pointer to the BPF value
func (c EndpointConfig) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&c) }

// endpoint provides access to the properties of an endpoint that are relevant
// for configuring the BPF program for the endpoint.
type endpoint interface {
	GetIngressPolicyEnabledLocked() bool
	GetEgressPolicyEnabledLocked() bool
}

// EndpointConfigMap is a map type for interfacing with endpoint BPF config.
type EndpointConfigMap struct {
	Map  *bpf.Map
	path string
	Fd   int
}

// GetConfig creates a EndpointConfig structure using the endpoint's
// configuration.
func GetConfig(e endpoint) *EndpointConfig {
	value := EndpointConfig{}
	if !e.GetIngressPolicyEnabledLocked() {
		value.Flags |= SkipPolicyIngress
	}
	if !e.GetEgressPolicyEnabledLocked() {
		value.Flags |= SkipPolicyEgress
	}

	return &value
}

// Update pushes the configuration options from the specified endpoint into the
// configuration map.
func (m *EndpointConfigMap) Update(value *EndpointConfig) error {
	return m.Map.Update(configKey, value)
}

// OpenMap attempts to open or create a BPF config map at the specified path.
// On success, it returns a map and whether the map was newly created, or
// otherwise an error.
func OpenMap(path string) (*EndpointConfigMap, bool, error) {

	newMap := bpf.NewMap("cilium_lb4_services",
		bpf.BPF_MAP_TYPE_ARRAY,
		int(unsafe.Sizeof(uint32(0))),
		int(unsafe.Sizeof(EndpointConfig{})),
		MaxEntries,
		0,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := Key{}, EndpointConfig{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}

			return k, v, nil
		}).WithCache()

	isNewMap, err := newMap.OpenOrCreate()

	if err != nil {
		return nil, false, err
	}

	m := &EndpointConfigMap{Map: newMap, path: path, Fd: newMap.GetFd()}

	return m, isNewMap, nil
}

// OpenMapWithName attempts to open or create a BPF config map at the specified
// path with the specified name.
// On success, it returns a map and whether the map was newly created, or
// otherwise an error.
func OpenMapWithName(path, name string) (*EndpointConfigMap, bool, error) {

	newMap := bpf.NewMap(name,
		bpf.BPF_MAP_TYPE_ARRAY,
		int(unsafe.Sizeof(uint32(0))),
		int(unsafe.Sizeof(EndpointConfig{})),
		MaxEntries,
		0,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := Key{}, EndpointConfig{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}
			fmt.Printf("k: %d, v: %b", k, v.Flags)
			return k, v, nil
		}).WithCache()

	isNewMap, err := newMap.OpenOrCreate()

	if err != nil {
		return nil, false, err
	}

	m := &EndpointConfigMap{Map: newMap, path: path, Fd: newMap.GetFd()}

	return m, isNewMap, nil
}

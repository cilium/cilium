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

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"

	"github.com/sirupsen/logrus"
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

	binMap = map[uint]string{
		0: "POLICY_INGRESS",
		1: "POLICY_EGRESS",
	}
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
				continue
			}
		} else if bitVal == 0 {
			if flag, ok := binMap[i]; ok {
				buffer.WriteString(flag)
				buffer.WriteString(",")
				continue
			}
		}
		buffer.WriteString(fmt.Sprintf("%04x,", 1<<i))
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
	return fmt.Sprintf("%d", k.Bits)
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *Key) NewValue() bpf.MapValue { return &EndpointConfig{} }

func (cfg *EndpointConfig) String() string {
	// TODO - use a tabwriter for CLI consistency?
	return fmt.Sprintf("%s, %d, %d, %s, %s, %d, %d, %s", cfg.Flags.String(), cfg.SecurityIdentity, cfg.SecurityIdentityNB, cfg.IPv4.String(), cfg.IPv6.String(), cfg.LXCID, cfg.LXCIDNB, cfg.NodeMAC.String())
}

// EndpointConfig represents the value of the endpoint's BPF map.
//
// Must be in sync with struct config_value in <bpf/lib/common.h>
type EndpointConfig struct {
	Flags Flags
	// NOTE: everything below this comment is not plumbed yet. This will be done
	// through future work. See GH-6273.
	IPv4 types.IPv4
	IPv6 types.IPv6
	// TODO: put lxcmap.MAC into its own pkg?
	NodeMAC            lxcmap.MAC
	LXCID              uint16
	LXCIDNB            uint16
	SecurityIdentity   uint32
	SecurityIdentityNB uint32
	Pad                uint32
}

// GetValuePtr returns the unsafe pointer to the BPF value
func (cfg *EndpointConfig) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(cfg) }

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
// configuration. The endpoint parameter should have its mutex held.
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
	configKey := &Key{Bits: 0}
	return m.Map.Update(configKey, value)
}

// Close closes the FD of the given CofigMap. Returns an error if the close
// operation failed. If the close operation succeeds, pm's file descriptor
// is set to zero.
func (m *EndpointConfigMap) Close() error {
	log.WithFields(logrus.Fields{
		logfields.BPFMapPath: m.path,
		logfields.BPFMapFD:   m.Fd,
	}).Debug("closing ConfigMap")
	err := bpf.ObjClose(m.Fd)

	// Unconditionally set file descriptor to zero so that if accesses are
	// attempted on this ConfigMap even after this call to Close, the accesses
	// aren't to a file descriptor that has been reassigned elsewhere. Even
	// if the close fails, per close(2) manpages:
	//
	// "on Linux and many other implementations, where, as with other errors that
	// may be reported by close(), the file descriptor is guaranteed to be
	// closed".
	//
	// We are relying upon this behavior, so we can safely zero out the file
	// descriptor in the PolicyMap.
	m.Fd = 0

	return err
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
			return &k, &v, nil
		}).WithCache()

	isNewMap, err := newMap.OpenOrCreate()

	if err != nil {
		return nil, false, err
	}

	m := &EndpointConfigMap{Map: newMap, path: path, Fd: newMap.GetFd()}

	return m, isNewMap, nil
}

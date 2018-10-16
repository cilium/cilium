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
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/viper"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-ep-policy")

const (
	MapName = "cilium_ep_to_policy"

	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65535
)

type EndpointKey struct{ bpf.EndpointKey }
type EpPolicyFd struct{ Fd uint32 }

var (
	EpPolicyMap = bpf.NewMap(MapName,
		bpf.MapTypeHashOfMaps,
		int(unsafe.Sizeof(EndpointKey{})),
		int(unsafe.Sizeof(EpPolicyFd{})),
		MaxEntries,
		0,
		4,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k := EndpointKey{}
			v := EpPolicyFd{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}

			return &k, &v, nil
		},
	) //.WithCache()
)

func init() {
	fd, err := bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH,
		uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
		policymap.MaxEntries,
		0, 0)

	if err != nil {
		log.WithError(err).Warning("unable to create EP to policy map")
		return
	}

	EpPolicyMap.InnerId = uint32(fd)
	err = bpf.OpenAfterMount(EpPolicyMap)
	if err != nil {
		log.WithError(err).Warning("unable to open EP to policy map")
		return
	}
}

func (v EpPolicyFd) String() string              { return fmt.Sprintf("fd=%d", v.Fd) }
func (v EpPolicyFd) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v.Fd) }
func (k EndpointKey) NewValue() bpf.MapValue     { return &EpPolicyFd{} }

func NewEndpointKey(ip net.IP) *EndpointKey {
	return &EndpointKey{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

func WriteEndpoint(keys []*lxcmap.EndpointKey, fd int) error {
	if viper.GetBool(option.SockopsEnableName) == false {
		return nil
	}

	if fd < 0 {
		return fmt.Errorf("WriteEndpoint invalid policy fd %d", fd)
	}

	fmt.Printf("WriteEndpoint %d\n", fd)

	/* Casting file desriptor into uint32 required by BPF syscall */
	epFd := &EpPolicyFd{Fd: uint32(fd)}

	for _, v := range keys {
		if err := EpPolicyMap.Update(v, epFd); err != nil {
			return err
		}
	}
	return nil
}

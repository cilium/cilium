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

package policymap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// GlobalMapName is the name for the global policy map which maps
	// endpoint IDs to the fd for the program which implements its policy.
	GlobalMapName = "cilium_policy"
)

// PolicyPlumbingMap maps endpoint IDs to the fd for the program which
// implements its policy.
type PolicyPlumbingMap struct {
	*bpf.Map
}

type plumbingKey struct {
	key uint32
}

type plumbingValue struct {
	fd uint32
}

func (k *plumbingKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *plumbingKey) NewValue() bpf.MapValue    { return &plumbingValue{} }

func (k *plumbingKey) String() string {
	return fmt.Sprintf("Endpoint: %d", k.key)
}

func (v *plumbingValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (v *plumbingValue) String() string {
	return fmt.Sprintf("fd: %d", v.fd)
}

// RemoveGlobalMapping removes the mapping from the specified endpoint ID to
// the BPF policy program for that endpoint.
func RemoveGlobalMapping(id uint32) error {
	gpm, err := OpenGlobalMap()
	if err == nil {
		k := plumbingKey{
			key: id,
		}
		err = gpm.Map.Delete(&k)
		gpm.Close()
	}

	return err
}

// OpenGlobalMap opens the map that maps endpoint IDs to program file
// descriptors, which allows tail calling into the policy datapath code from
// other BPF programs.
func OpenGlobalMap() (*PolicyPlumbingMap, error) {
	m, err := bpf.OpenMap(GlobalMapName)
	if err != nil {
		return nil, err
	}
	return &PolicyPlumbingMap{Map: m}, nil
}

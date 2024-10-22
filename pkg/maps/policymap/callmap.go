// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
)

// PolicyPlumbingMap maps endpoint IDs to the fd for the program which
// implements its policy.
type PolicyPlumbingMap struct {
	*bpf.Map
}

type PlumbingKey struct {
	key uint32
}

type PlumbingValue struct {
	fd uint32
}

func (k *PlumbingKey) String() string {
	return fmt.Sprintf("Endpoint: %d", k.key)
}
func (k *PlumbingKey) New() bpf.MapKey { return &PlumbingKey{} }

func (v *PlumbingValue) String() string {
	return fmt.Sprintf("fd: %d", v.fd)
}

func (k *PlumbingValue) New() bpf.MapValue { return &PlumbingValue{} }

// RemoveGlobalMapping removes the mapping from the specified endpoint ID to
// the BPF policy program for that endpoint.
func RemoveGlobalMapping(id uint32, haveEgressCallMap bool) error {
	gpm, err := OpenCallMap(PolicyCallMapName)
	if err == nil {
		k := PlumbingKey{
			key: id,
		}
		err = gpm.Map.Delete(&k)
		gpm.Close()
	}
	if haveEgressCallMap {
		gpm, err2 := OpenCallMap(PolicyEgressCallMapName)
		if err2 == nil {
			k := PlumbingKey{
				key: id,
			}
			err2 = gpm.Map.Delete(&k)
			gpm.Close()
		}
		if err == nil {
			return err2
		}
	}

	return err
}

// OpenCallMap opens the map that maps endpoint IDs to program file
// descriptors, which allows tail calling into the policy datapath code from
// other BPF programs.
func OpenCallMap(name string) (*PolicyPlumbingMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(name), &PlumbingKey{}, &PlumbingValue{})
	if err != nil {
		return nil, err
	}
	return &PolicyPlumbingMap{Map: m}, nil
}

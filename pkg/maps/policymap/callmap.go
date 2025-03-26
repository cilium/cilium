// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
)

// PolicyPlumbingMap maps endpoint IDs to the fd for the program which
// implements its policy.
type PolicyPlumbingMap struct {
	*bpf.Map
}

type PlumbingKey struct {
	Key uint32
}

type PlumbingValue struct {
	Fd uint32
}

func (k *PlumbingKey) String() string {
	return fmt.Sprintf("Endpoint: %d", k.Key)
}
func (k *PlumbingKey) New() bpf.MapKey { return &PlumbingKey{} }

func (v *PlumbingValue) String() string {
	return fmt.Sprintf("fd: %d", v.Fd)
}

func (k *PlumbingValue) New() bpf.MapValue { return &PlumbingValue{} }

// RemoveGlobalMapping removes the mapping from the specified endpoint ID to
// the BPF policy program for that endpoint.
func RemoveGlobalMapping(logger *slog.Logger, id uint32, haveEgressCallMap bool) error {
	gpm, err := OpenCallMap(logger, PolicyCallMapName)
	if err == nil {
		k := PlumbingKey{
			Key: id,
		}
		err = gpm.Map.Delete(&k)
		gpm.Close()
	}
	if haveEgressCallMap {
		gpm, err2 := OpenCallMap(logger, PolicyEgressCallMapName)
		if err2 == nil {
			k := PlumbingKey{
				Key: id,
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
func OpenCallMap(logger *slog.Logger, name string) (*PolicyPlumbingMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, name), &PlumbingKey{}, &PlumbingValue{})
	if err != nil {
		return nil, err
	}
	return &PolicyPlumbingMap{Map: m}, nil
}

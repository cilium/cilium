// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

// PolicyPlumbingMap maps endpoint IDs to the fd for the program which
// implements its policy.
type PolicyPlumbingMap struct {
	*bpf.Map
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type PlumbingKey struct {
	key uint32
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type PlumbingValue struct {
	fd uint32
}

func (k *PlumbingKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *PlumbingKey) NewValue() bpf.MapValue    { return &PlumbingValue{} }

func (k *PlumbingKey) String() string {
	return fmt.Sprintf("Endpoint: %d", k.key)
}

func (v *PlumbingValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (v *PlumbingValue) String() string {
	return fmt.Sprintf("fd: %d", v.fd)
}

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
	m, err := bpf.OpenMap(bpf.MapPath(name))
	if err != nil {
		return nil, err
	}
	m.MapKey = &PlumbingKey{}
	m.MapValue = &PlumbingValue{}
	return &PolicyPlumbingMap{Map: m}, nil
}

// CallString returns the string which indicates the calls map by index in the
// ELF, and index into that call map for a specific endpoint.
//
// Derived from __section_tail(CILIUM_MAP_POLICY, NAME) per bpf/lib/tailcall.h.
func CallString(id uint16) string {
	return fmt.Sprintf("1/%#04x", id)
}

// EgressCallString returns the string which indicates the calls map by index in the
// ELF, and index into that call map for a specific endpoint.
//
// Derived from __section_tail(CILIUM_MAP_EGRESSPOLICY, NAME) per bpf/lib/tailcall.h.
func EgressCallString(id uint16) string {
	return fmt.Sprintf("4/%#04x", id)
}

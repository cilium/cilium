// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/ebpf"
)

const (
	MapName = "cilium_auth_map"
)

// Map provides access to the eBPF map auth.
type Map interface {
	// Lookup returns the auth map object associated with the provided
	// (local identity, remote identity, remote host id, auth type) quadruple.
	Lookup(key AuthKey) (AuthInfo, error)

	// Update inserts or updates the auth map object associated with the provided
	// (local identity, remote identity, remote host id, auth type) quadruple.
	Update(key AuthKey, expiration utime.UTime) error

	// Delete deletes the auth map object associated with the provided
	// (local identity, remote identity, remote host id, auth type) quadruple.
	Delete(key AuthKey) error

	// IterateWithCallback iterates through all the keys/values of an auth map,
	// passing each key/value pair to the cb callback.
	IterateWithCallback(cb IterateCallback) error
}

type authMap struct {
	bpfMap *ebpf.Map
}

func newMap(maxEntries int) *authMap {
	return &authMap{
		bpfMap: ebpf.NewMap(&ebpf.MapSpec{
			Name:       MapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(AuthKey{})),
			ValueSize:  uint32(unsafe.Sizeof(AuthInfo{})),
			MaxEntries: uint32(maxEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		}),
	}
}

// LoadAuthMap loads the pre-initialized auth map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadAuthMap() (Map, error) {
	bpfMap, err := ebpf.LoadRegisterMap(MapName)
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf map: %w", err)
	}

	return &authMap{bpfMap: bpfMap}, nil
}

func (m *authMap) init() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *authMap) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}

func (m *authMap) Update(key AuthKey, expiration utime.UTime) error {
	val := AuthInfo{Expiration: expiration}
	return m.bpfMap.Update(key, val, 0)
}

func (m *authMap) Delete(key AuthKey) error {
	return m.bpfMap.Delete(key)
}

func (m *authMap) Lookup(key AuthKey) (AuthInfo, error) {
	val := AuthInfo{}
	err := m.bpfMap.Lookup(key, &val)
	return val, err
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an auth map.
type IterateCallback func(*AuthKey, *AuthInfo)

func (m *authMap) IterateWithCallback(cb IterateCallback) error {
	return m.bpfMap.IterateWithCallback(&AuthKey{}, &AuthInfo{},
		func(k, v interface{}) {
			key := k.(*AuthKey)
			value := v.(*AuthInfo)
			cb(key, value)
		},
	)
}

// AuthKey implements the bpf.MapKey interface.
//
// Must be in sync with struct auth_key in <bpf/lib/common.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type AuthKey struct {
	LocalIdentity  uint32 `align:"local_sec_label"`
	RemoteIdentity uint32 `align:"remote_sec_label"`
	RemoteNodeID   uint16 `align:"remote_node_id"`
	AuthType       uint8  `align:"auth_type"`
	Pad            uint8  `align:"pad"`
}

func (r *AuthKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(r) }

func (r *AuthKey) NewValue() bpf.MapValue { return &AuthInfo{} }

func (r *AuthKey) String() string {
	return fmt.Sprintf("localIdentity=%d, remoteIdentity=%d, remoteNodeID=%d, authType=%d", r.LocalIdentity, r.RemoteIdentity, r.RemoteNodeID, r.AuthType)
}

// AuthInfo implements the bpf.MapValue interface.
//
// Must be in sync with struct auth_info in <bpf/lib/common.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type AuthInfo struct {
	Expiration utime.UTime `align:"expiration"`
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (r *AuthInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(r) }

func (r *AuthInfo) String() string {
	return fmt.Sprintf("expiration=%q", r.Expiration)
}

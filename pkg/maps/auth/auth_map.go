// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
)

const (
	MapName = "cilium_auth_map"
)

var (
	authMap     *Map
	authMapInit = &sync.Once{}
)

type Map struct {
	*ebpf.Map
}

// AuthMap returns the initialized auth map
func AuthMap() *Map {
	return authMap
}

// InitAuthMap initializes the auth map.
func InitAuthMap(maxEntries int) error {
	return initMap(maxEntries, true)
}

// OpenAuthMap opens the auth map for access.
func OpenAuthMap() error {
	return initMap(0, false)
}

func initMap(maxEntries int, create bool) error {
	var initErr error

	authMapInit.Do(func() {
		var m *ebpf.Map

		if create {
			m = ebpf.NewMap(&ebpf.MapSpec{
				Name:       MapName,
				Type:       ebpf.Hash,
				KeySize:    uint32(unsafe.Sizeof(AuthKey{})),
				ValueSize:  uint32(unsafe.Sizeof(AuthInfo{})),
				MaxEntries: uint32(maxEntries),
				Flags:      unix.BPF_F_NO_PREALLOC,
				Pinning:    ebpf.PinByName,
			})
			if err := m.OpenOrCreate(); err != nil {
				initErr = err
				return
			}
		} else {
			var err error

			if m, err = ebpf.LoadRegisterMap(MapName); err != nil {
				initErr = err
				return
			}
		}

		authMap = &Map{Map: m}
	})

	return initErr
}

// Update inserts or updates the auth map object associated with the provided
// (local identity, remote identity, remote host id, auth type) quadruple.
func (m *Map) Update(localIdentity identity.NumericIdentity, remoteIdentity identity.NumericIdentity, remoteNodeID uint16, authType policy.AuthType, expiration uint64) error {
	key := newAuthKey(localIdentity, remoteIdentity, remoteNodeID, authType)
	val := AuthInfo{Expiration: expiration}
	return m.Map.Update(key, val, 0)
}

// Delete deletes the auth map object associated with the provided
// (local identity, remote identity, remote host id, auth type) quadruple.
func (m *Map) Delete(localIdentity identity.NumericIdentity, remoteIdentity identity.NumericIdentity, remoteNodeID uint16, authType policy.AuthType) error {
	key := newAuthKey(localIdentity, remoteIdentity, remoteNodeID, authType)
	return m.Map.Delete(key)
}

// Lookup returns the auth map object associated with the provided
// (local identity, remote identity, remote host id, auth type) quadruple.
func (m *Map) Lookup(localIdentity identity.NumericIdentity, remoteIdentity identity.NumericIdentity, remoteNodeID uint16, authType policy.AuthType) (*AuthInfo, error) {
	key := newAuthKey(localIdentity, remoteIdentity, remoteNodeID, authType)
	val := AuthInfo{}

	err := m.Map.Lookup(&key, &val)

	return &val, err
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an auth map.
type IterateCallback func(*AuthKey, *AuthInfo)

// IterateWithCallback iterates through all the keys/values of an auth map,
// passing each key/value pair to the cb callback.
func (m *Map) IterateWithCallback(cb IterateCallback) error {
	return m.Map.IterateWithCallback(&AuthKey{}, &AuthInfo{},
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

func newAuthKey(localIdentity identity.NumericIdentity, remoteIdentity identity.NumericIdentity, remoteNodeID uint16, authType policy.AuthType) AuthKey {
	return AuthKey{
		LocalIdentity:  localIdentity.Uint32(),
		RemoteIdentity: remoteIdentity.Uint32(),
		RemoteNodeID:   remoteNodeID,
		AuthType:       authType.Uint8(),
	}
}

// AuthInfo implements the bpf.MapValue interface.
//
// Must be in sync with struct auth_info in <bpf/lib/common.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type AuthInfo struct {
	Expiration uint64 `align:"expiration"`
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (r *AuthInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(r) }

func (r *AuthInfo) String() string {
	return fmt.Sprintf("expiration=%d", r.Expiration)
}

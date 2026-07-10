// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
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

	// MaxEntries returns the maximum number of entries the auth map can hold.
	MaxEntries() uint32
}

type authMap struct {
	m *bpf.Map
}

// LoadAuthMap loads the pre-initialized auth map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadAuthMap(logger *slog.Logger) (Map, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, MapName), &AuthKey{}, &AuthInfo{})
	return &authMap{m: m}, err
}

func (m *authMap) Update(key AuthKey, expiration utime.UTime) error {
	val := AuthInfo{Expiration: expiration}
	return m.m.Update(&key, &val)
}

func (m *authMap) Delete(key AuthKey) error {
	return m.m.Delete(&key)
}

func (m *authMap) Lookup(key AuthKey) (AuthInfo, error) {
	val, err := m.m.Lookup(&key)
	if err != nil {
		return AuthInfo{}, err
	}
	return *val.(*AuthInfo), nil
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an auth map.
type IterateCallback func(*AuthKey, *AuthInfo)

func (m *authMap) IterateWithCallback(cb IterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*AuthKey)
		value := v.(*AuthInfo)
		cb(key, value)
	})
}

func (m *authMap) MaxEntries() uint32 {
	return m.m.MaxEntries()
}

// AuthKey implements the bpf.MapKey interface.
//
// Must be in sync with struct auth_key in <bpf/lib/common.h>
type AuthKey struct {
	LocalIdentity  uint32 `align:"local_sec_label"`
	RemoteIdentity uint32 `align:"remote_sec_label"`
	RemoteNodeID   uint16 `align:"remote_node_id"`
	AuthType       uint8  `align:"auth_type"`
	Pad            uint8  `align:"pad"`
}

func (r *AuthKey) String() string {
	return fmt.Sprintf("localIdentity=%d, remoteIdentity=%d, remoteNodeID=%d, authType=%d", r.LocalIdentity, r.RemoteIdentity, r.RemoteNodeID, r.AuthType)
}
func (r *AuthKey) New() bpf.MapKey { return &AuthKey{} }

// AuthInfo implements the bpf.MapValue interface.
//
// Must be in sync with struct auth_info in <bpf/lib/common.h>
type AuthInfo struct {
	Expiration utime.UTime `align:"expiration"`
}

func (r *AuthInfo) String() string {
	return fmt.Sprintf("expiration=%q", r.Expiration)
}

func (r *AuthInfo) New() bpf.MapValue { return &AuthInfo{} }

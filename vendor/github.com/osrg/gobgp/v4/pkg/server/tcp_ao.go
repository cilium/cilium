// Copyright (C) 2026 The GoBGP Authors.
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

package server

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type tcpAoKeychain struct {
	mu   sync.RWMutex
	name string
	keys map[uint8]netutils.TCPAOKey
}

type tcpAoKeychainStore struct {
	// keychains must only be accessed from mgmtOperation callbacks while shared.mu is held.
	keychains map[string]*tcpAoKeychain
}

func newTcpAoKeychainStore() *tcpAoKeychainStore {
	return &tcpAoKeychainStore{keychains: make(map[string]*tcpAoKeychain)}
}

func (s *tcpAoKeychainStore) addKeychain(chain *tcpAoKeychain) {
	s.keychains[chain.name] = chain
}

func (s *tcpAoKeychainStore) getKeychain(name string) (*tcpAoKeychain, bool) {
	chain, ok := s.keychains[name]
	return chain, ok
}

func (s *tcpAoKeychainStore) getAllKeychains() []*tcpAoKeychain {
	return slices.Collect(maps.Values(s.keychains))
}

func (s *tcpAoKeychainStore) deleteKeychain(name string) bool {
	chain, ok := s.keychains[name]
	if !ok {
		return false
	}
	chain.clearKeys()
	delete(s.keychains, name)
	return true
}

func (s *tcpAoKeychainStore) clearAllKeychains() {
	for _, chain := range s.keychains {
		chain.clearKeys()
	}
	clear(s.keychains)
}

func newTcpAoKeychain(a *api.TcpAoKeychain) (*tcpAoKeychain, error) {
	keys, err := newTcpAoKeys(a.Name, a.Keys)
	if err != nil {
		return nil, err
	}
	if err := netutils.ValidateTCPAOKeys(keys); err != nil {
		clearTcpAoKeys(keys)
		return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q: %v", a.Name, err)
	}
	keyMap := make(map[uint8]netutils.TCPAOKey, len(keys))
	for _, key := range keys {
		keyMap[key.SendID] = key
	}
	return &tcpAoKeychain{name: a.Name, keys: keyMap}, nil
}

// newTcpAoKeys converts API keys and validates each key on its own. Checks that
// span the whole key set, such as the key count and duplicate IDs, are left to
// the caller. An update must validate the merged key set, not just the keys it
// adds.
func newTcpAoKeys(chainName string, keys []*api.TcpAoKey) ([]netutils.TCPAOKey, error) {
	result := make([]netutils.TCPAOKey, 0, len(keys))
	for i, key := range keys {
		converted, err := newTcpAoKey(chainName, i, key)
		if err != nil {
			clearTcpAoKeys(result)
			return nil, err
		}
		result = append(result, converted)
	}
	return result, nil
}

// newTcpAoKey converts one API key that carries keying material. Requests that
// only identify a key, such as the delete list of an update, use tcpAoKeyIDs.
func newTcpAoKey(chainName string, index int, key *api.TcpAoKey) (netutils.TCPAOKey, error) {
	sendID, receiveID, err := tcpAoKeyIDs(chainName, index, key)
	if err != nil {
		return netutils.TCPAOKey{}, err
	}
	algorithm, ok := tcpAoAlgorithm(key.Algorithm)
	if !ok {
		return netutils.TCPAOKey{}, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key at index %d has unsupported algorithm %s", chainName, index, key.Algorithm)
	}
	return netutils.TCPAOKey{
		SendID:            sendID,
		ReceiveID:         receiveID,
		Algorithm:         algorithm,
		ExcludeTCPOptions: key.ExcludeTcpOptions,
		MasterKey:         bytes.Clone(key.MasterKey),
	}, nil
}

// tcpAoKeyIDs converts the key IDs of one API key. RFC 5925 carries the KeyID in
// a single byte, so a value above 255 cannot be represented. The API uses uint32
// because proto3 has no 8-bit integer type.
func tcpAoKeyIDs(chainName string, index int, key *api.TcpAoKey) (uint8, uint8, error) {
	if key == nil {
		return 0, 0, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key at index %d is nil", chainName, index)
	}
	if key.SendId > math.MaxUint8 {
		return 0, 0, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key at index %d has send ID %d outside 0..255", chainName, index, key.SendId)
	}
	if key.ReceiveId > math.MaxUint8 {
		return 0, 0, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key at index %d has receive ID %d outside 0..255", chainName, index, key.ReceiveId)
	}
	return uint8(key.SendId), uint8(key.ReceiveId), nil
}

// tcpAoAlgorithm maps an API algorithm to the netutils one. The two enums are
// mapped explicitly so that they can be changed independently.
func tcpAoAlgorithm(algorithm api.TcpAoAlgorithm) (netutils.TCPAOAlgorithm, bool) {
	switch algorithm {
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96:
		return netutils.TCPAOAlgorithmHMACSHA1, true
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96:
		return netutils.TCPAOAlgorithmAES128CMAC, true
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96:
		return netutils.TCPAOAlgorithmHMACSHA256MAC96, true
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128:
		return netutils.TCPAOAlgorithmHMACSHA256MAC128, true
	default:
		return netutils.TCPAOAlgorithmUnspecified, false
	}
}

func apiTcpAoAlgorithm(algorithm netutils.TCPAOAlgorithm) api.TcpAoAlgorithm {
	switch algorithm {
	case netutils.TCPAOAlgorithmHMACSHA1:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96
	case netutils.TCPAOAlgorithmAES128CMAC:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96
	case netutils.TCPAOAlgorithmHMACSHA256MAC96:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96
	case netutils.TCPAOAlgorithmHMACSHA256MAC128:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128
	default:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_UNSPECIFIED
	}
}

// validateTcpAoKeychainUpdate converts the keys of an update request and checks
// the result against the current contents of the keychain. It returns the keys
// to add and the keys to delete.
func validateTcpAoKeychainUpdate(keychain *tcpAoKeychain, request *api.UpdateTcpAoKeychainRequest) ([]netutils.TCPAOKey, []netutils.TCPAOKey, error) {
	var deleted []netutils.TCPAOKey
	seen := make(map[uint8]struct{}, len(request.DeleteKeys))
	for i, delKey := range request.DeleteKeys {
		sendID, receiveID, err := tcpAoKeyIDs(request.Name, i, delKey)
		if err != nil {
			return nil, nil, err
		}
		if _, duplicate := seen[sendID]; duplicate {
			return nil, nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q delete request contains duplicate send ID %d", request.Name, sendID)
		}
		key, exists := keychain.getKey(sendID, receiveID)
		if !exists {
			return nil, nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q does not contain key with send ID %d and receive ID %d", request.Name, sendID, receiveID)
		}
		seen[sendID] = struct{}{}
		deleted = append(deleted, key)
	}

	added, err := newTcpAoKeys(request.Name, request.AddKeys)
	if err != nil {
		return nil, nil, err
	}
	if err := netutils.ValidateTCPAOKeys(keychain.mergedKeys(added, deleted)); err != nil {
		clearTcpAoKeys(added)
		return nil, nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q: %v", request.Name, err)
	}
	return added, deleted, nil
}

// clearTcpAoKeys zeroes the master key of every key. Only call it for keys that
// no keychain holds, because the master key storage is shared with the keychain.
func clearTcpAoKeys(keys []netutils.TCPAOKey) {
	for _, key := range keys {
		clear(key.MasterKey)
	}
}

func (c *tcpAoKeychain) toAPIKeychain() *api.TcpAoKeychain {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := &api.TcpAoKeychain{
		Name: c.name,
		Keys: make([]*api.TcpAoKey, 0, len(c.keys)),
	}
	sendIDs := make([]uint8, 0, len(c.keys))
	for sendID := range c.keys {
		sendIDs = append(sendIDs, sendID)
	}
	slices.Sort(sendIDs)
	for _, sendID := range sendIDs {
		key := c.keys[sendID]
		result.Keys = append(result.Keys, &api.TcpAoKey{
			SendId:            uint32(key.SendID),
			ReceiveId:         uint32(key.ReceiveID),
			Algorithm:         apiTcpAoAlgorithm(key.Algorithm),
			ExcludeTcpOptions: key.ExcludeTCPOptions,
			// MasterKey is intentionally omitted
		})
	}
	return result
}

func (c *tcpAoKeychain) hasSendID(sendID uint8) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.keys[sendID]
	return ok
}

func (c *tcpAoKeychain) getKey(sendID, receiveID uint8) (netutils.TCPAOKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[sendID]
	if !ok || key.ReceiveID != receiveID {
		return netutils.TCPAOKey{}, false
	}
	return key, true
}

// mergedKeys returns the key set the keychain would hold once the given keys are
// deleted and added. The returned keys share master key storage with the
// keychain, so the caller must not clear them.
func (c *tcpAoKeychain) mergedKeys(added, deleted []netutils.TCPAOKey) []netutils.TCPAOKey {
	c.mu.RLock()
	defer c.mu.RUnlock()

	remaining := maps.Clone(c.keys)
	for _, key := range deleted {
		delete(remaining, key.SendID)
	}
	merged := slices.Collect(maps.Values(remaining))
	return append(merged, added...)
}

func (c *tcpAoKeychain) updateKeys(added, deleted []netutils.TCPAOKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, deletedKey := range deleted {
		key, ok := c.keys[deletedKey.SendID]
		if !ok || key.ReceiveID != deletedKey.ReceiveID {
			continue
		}
		clear(key.MasterKey)
		delete(c.keys, deletedKey.SendID)
	}
	for _, key := range added {
		c.keys[key.SendID] = key
	}
}

func (c *tcpAoKeychain) clearKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, key := range c.keys {
		clear(key.MasterKey)
	}
	clear(c.keys)
}

func (c *tcpAoKeychain) socketKeys(preferredSendID uint8) (*tcpAoSocketKeys, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.keys) == 0 {
		return nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q does not contain any key", c.name)
	}
	if _, ok := c.keys[preferredSendID]; !ok {
		return nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q has no key with send ID %d", c.name, preferredSendID)
	}
	keys := slices.Collect(maps.Values(c.keys))
	return newTcpAoSocketKeys(keys, &preferredSendID), nil
}

// tcpAoSocketKeys is a short-lived TCP-AO key snapshot used for socket operations.
// Its master keys are deep-copied while the keychain is locked, allowing the
// potentially blocking socket calls to run without holding keychain lock.
// The preferred send ID is optional: listeners and key deletion only need the keys;
// active and accepted connections also select a send ID.
type tcpAoSocketKeys struct {
	keys            []netutils.TCPAOKey
	preferredSendID *uint8
}

func newTcpAoSocketKeys(keys []netutils.TCPAOKey, preferredSendID *uint8) *tcpAoSocketKeys {
	socketKeys := &tcpAoSocketKeys{keys: make([]netutils.TCPAOKey, 0, len(keys))}
	for _, key := range keys {
		key.MasterKey = append([]byte{}, key.MasterKey...)
		socketKeys.keys = append(socketKeys.keys, key)
	}
	if preferredSendID != nil {
		preferred := *preferredSendID
		socketKeys.preferredSendID = &preferred
	}
	return socketKeys
}

func (k *tcpAoSocketKeys) netutilsConfig(selectPreferred bool) (netutils.TCPAOConfig, error) {
	if k == nil {
		return netutils.TCPAOConfig{}, fmt.Errorf("missing TCP-AO socket keys")
	}
	result := netutils.TCPAOConfig{Keys: k.keys}
	if selectPreferred {
		if k.preferredSendID == nil {
			return netutils.TCPAOConfig{}, fmt.Errorf("missing TCP-AO preferred send ID")
		}
		preferred := *k.preferredSendID
		result.PreferredSendID = &preferred
	}
	return result, nil
}

func addTcpAoKeys(raw syscall.RawConn, peerAddr netip.Addr, interfaceName string, socketKeys *tcpAoSocketKeys, selectPreferred bool) error {
	config, err := socketKeys.netutilsConfig(selectPreferred)
	if err != nil {
		return err
	}
	return netutils.AddTCPAOKeysSockopt(raw, tcpAoPeerPrefix(peerAddr), interfaceName, config)
}

// deleteTcpAoKeys removes the given keys from one socket. Pass delAsync only
// for a listening socket; the kernel rejects it on any other socket.
func deleteTcpAoKeys(raw syscall.RawConn, peerAddr netip.Addr, interfaceName string, socketKeys *tcpAoSocketKeys, delAsync bool) error {
	config, err := socketKeys.netutilsConfig(false)
	if err != nil {
		return err
	}
	return netutils.DeleteTCPAOKeysSockopt(raw, tcpAoPeerPrefix(peerAddr), interfaceName, config, delAsync)
}

func addTcpAoKeysToListeners(listeners []*net.TCPListener, peerAddr netip.Addr, interfaceName string, socketKeys *tcpAoSocketKeys) error {
	configured := make([]*net.TCPListener, 0, len(listeners))
	rollback := func(cause error) error {
		errs := []error{cause}
		for _, err := range deleteTcpAoKeysFromListeners(configured, peerAddr, interfaceName, socketKeys) {
			errs = append(errs, fmt.Errorf("failed to roll back TCP-AO listener configuration: %w", err))
		}
		return errors.Join(errs...)
	}
	for _, listener := range listeners {
		raw, err := listener.SyscallConn()
		if err != nil {
			return rollback(err)
		}
		// AddTCPAOKeysSockopt installs keys one at a time and can fail
		// after partially configuring the listener.
		configured = append(configured, listener)
		if err := addTcpAoKeys(raw, peerAddr, interfaceName, socketKeys, false); err != nil {
			return rollback(err)
		}
	}
	return nil
}

func deleteTcpAoKeysFromListeners(listeners []*net.TCPListener, peerAddr netip.Addr, interfaceName string, socketKeys *tcpAoSocketKeys) []error {
	var result []error
	for _, listener := range listeners {
		raw, err := listener.SyscallConn()
		if err == nil {
			err = deleteTcpAoKeys(raw, peerAddr, interfaceName, socketKeys, true)
		}
		if err != nil {
			result = append(result, err)
		}
	}
	return result
}

func setTcpAoConnectionRNext(conn net.Conn, socketKeys *tcpAoSocketKeys) error {
	raw, err := tcpAoRawConn(conn)
	if err != nil {
		return err
	}
	config, err := socketKeys.netutilsConfig(true)
	if err != nil {
		return err
	}
	return netutils.SetTCPAOKeySockopt(raw, config, true, false)
}

func getTcpAoConnectionState(conn net.Conn) (*api.TcpAoPeerState, error) {
	raw, err := tcpAoRawConn(conn)
	if err != nil {
		return nil, err
	}
	keyStates, err := netutils.GetTCPAOKeyStateSockopt(raw)
	if err != nil {
		return nil, err
	}
	counters, err := netutils.GetTCPAOSocketCountersSockopt(raw)
	if err != nil {
		return nil, err
	}
	state := &api.TcpAoPeerState{
		Keys:               make([]*api.TcpAoKeyState, 0, len(keyStates)),
		PacketsKeyNotFound: counters.PacketsKeyNotFound,
		PacketsAoRequired:  counters.PacketsAORequired,
		PacketsDroppedIcmp: counters.PacketsDroppedICMP,
	}
	for _, key := range keyStates {
		state.Keys = append(state.Keys, &api.TcpAoKeyState{
			SendId:      uint32(key.SendID),
			ReceiveId:   uint32(key.ReceiveID),
			Current:     key.Current,
			ReceiveNext: key.ReceiveNext,
			PacketsGood: key.PacketsGood,
			PacketsBad:  key.PacketsBad,
		})
	}
	return state, nil
}

func tcpAoPeerPrefix(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen())
}

func tcpAoRawConn(conn net.Conn) (syscall.RawConn, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("TCP connection does not expose a syscall connection")
	}
	return syscallConn.SyscallConn()
}

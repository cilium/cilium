// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// PolicyCallMapName is the name of the map to do tail calls into policy
	// enforcement programs.
	PolicyCallMapName = "cilium_call_policy"

	// PolicyEgressCallMapName is the name of the map to do tail calls into egress policy
	// enforcement programs.
	PolicyEgressCallMapName = "cilium_egresscall_policy"

	// PolicyCallMaxEntries is the upper limit of entries in the program
	// array for the tail calls to jump into the endpoint specific policy
	// programs. This number *MUST* be identical to the maximum endpoint ID.
	PolicyCallMaxEntries = ^uint16(0)
)

// CallKey is the index into the prog array map.
type CallKey struct {
	Index uint32
}

// CallValue is the program ID in the prog array map.
type CallValue struct {
	ProgID uint32
}

// String converts the key into a human readable string format.
func (k *CallKey) String() string  { return strconv.FormatUint(uint64(k.Index), 10) }
func (k *CallKey) New() bpf.MapKey { return &CallKey{} }

// String converts the value into a human readable string format.
func (v *CallValue) String() string    { return strconv.FormatUint(uint64(v.ProgID), 10) }
func (v *CallValue) New() bpf.MapValue { return &CallValue{} }

// RemoveGlobalMapping removes the mapping from the specified endpoint ID to
// the BPF policy program for that endpoint.
func RemoveGlobalMapping(logger *slog.Logger, id uint32) error {
	var errs error

	if m, err := openCallMap(logger, PolicyCallMapName); err != nil {
		errs = errors.Join(errs, fmt.Errorf("open global policy map: %w", err))
	} else {
		defer m.Close()
		k := CallKey{Index: id}
		if err := m.Delete(&k); err != nil {
			errs = errors.Join(errs, fmt.Errorf("delete endpoint id %d from global policy map: %w", id, err))
		}
	}

	if m, err := openCallMap(logger, PolicyEgressCallMapName); err != nil {
		errs = errors.Join(errs, fmt.Errorf("open global egress policy map: %w", err))
	} else {
		defer m.Close()
		k := CallKey{Index: id}
		if err := m.Delete(&k); err != nil {
			errs = errors.Join(errs, fmt.Errorf("delete endpoint id %d from global egress policy map: %w", id, err))
		}
	}

	return errs
}

// openCallMap opens the map that maps endpoint IDs to program file descriptors, which allows tail
// calling into the policy datapath code from other BPF programs.
func openCallMap(logger *slog.Logger, name string) (*bpf.Map, error) {
	return bpf.OpenMap(bpf.MapPath(logger, name), &CallKey{}, &CallValue{})
}

// initCallMap creates the policy call maps in the kernel.
func initCallMaps() error {
	policyCallMap := bpf.NewMap(PolicyCallMapName,
		ebpf.ProgramArray,
		&CallKey{},
		&CallValue{},
		int(PolicyCallMaxEntries),
		0,
	)
	if err := policyCallMap.Create(); err != nil {
		return err
	}

	policyEgressCallMap := bpf.NewMap(PolicyEgressCallMapName,
		ebpf.ProgramArray,
		&CallKey{},
		&CallValue{},
		int(PolicyCallMaxEntries),
		0,
	)
	return policyEgressCallMap.Create()
}

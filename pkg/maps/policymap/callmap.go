// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
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
func RemoveGlobalMapping(logger *slog.Logger, id uint32) error {
	var errs error

	if m, err := OpenCallMap(logger, PolicyCallMapName); err != nil {
		errs = errors.Join(errs, fmt.Errorf("open global policy map: %w", err))
	} else {
		defer m.Close()
		k := PlumbingKey{
			Key: id,
		}
		if err := m.Map.Delete(&k); err != nil {
			errs = errors.Join(errs, fmt.Errorf("delete endpoint id %d from global policy map: %w", id, err))
		}
	}

	if m, err := OpenCallMap(logger, PolicyEgressCallMapName); err != nil {
		errs = errors.Join(errs, fmt.Errorf("open global egress policy map: %w", err))
	} else {
		defer m.Close()
		k := PlumbingKey{
			Key: id,
		}
		if err := m.Map.Delete(&k); err != nil {
			errs = errors.Join(errs, fmt.Errorf("delete endpoint id %d from global egress policy map: %w", id, err))
		}
	}

	return errs
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

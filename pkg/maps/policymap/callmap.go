// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
)

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

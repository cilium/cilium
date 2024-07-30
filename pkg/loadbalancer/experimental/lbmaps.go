// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"errors"
	"math/rand/v2"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lbmap"
)

type serviceMaps interface {
	UpdateService(key lbmap.ServiceKey, value lbmap.ServiceValue) error
	DeleteService(key lbmap.ServiceKey) error
	DumpService(cb func(lbmap.ServiceKey, lbmap.ServiceValue)) error
}

type backendMaps interface {
	UpdateBackend(lbmap.BackendKey, lbmap.BackendValue) error
	DeleteBackend(lbmap.BackendKey) error
	DumpBackend(cb func(lbmap.BackendKey, lbmap.BackendValue)) error
}

type revNatMaps interface {
	UpdateRevNat(lbmap.RevNatKey, lbmap.RevNatValue) error
	DeleteRevNat(lbmap.RevNatKey) error
	DumpRevNat(cb func(lbmap.RevNatKey, lbmap.RevNatValue)) error
}

// lbmaps defines the map operations performed by the reconciliation.
// Depending on this interface instead of on the underlying maps allows
// testing the implementation with a fake map or injected errors.
type lbmaps interface {
	serviceMaps
	backendMaps
	revNatMaps

	// TODO rest of the maps
}

type realLBMaps struct {
}

// DeleteRevNat implements lbmaps.
func (r *realLBMaps) DeleteRevNat(key lbmap.RevNatKey) error {
	_, err := key.Map().SilentDelete(key)
	return err
}

// DumpRevNat implements lbmaps.
func (r *realLBMaps) DumpRevNat(cb func(lbmap.RevNatKey, lbmap.RevNatValue)) error {
	cbWrap := func(key bpf.MapKey, value bpf.MapValue) {
		cb(
			key.(lbmap.RevNatKey),
			value.(lbmap.RevNatValue),
		)
	}
	return errors.Join(
		lbmap.RevNat4Map.DumpWithCallback(cbWrap),
		lbmap.RevNat6Map.DumpWithCallback(cbWrap),
	)
}

// UpdateRevNat4 implements lbmaps.
func (r *realLBMaps) UpdateRevNat(key lbmap.RevNatKey, value lbmap.RevNatValue) error {
	return key.Map().Update(key, value)
}

// DumpBackend implements lbmaps.
func (r *realLBMaps) DumpBackend(cb func(lbmap.BackendKey, lbmap.BackendValue)) error {
	cbWrap := func(key bpf.MapKey, value bpf.MapValue) {
		cb(
			key.(lbmap.BackendKey),
			value.(lbmap.BackendValue).ToHost(),
		)
	}
	return errors.Join(
		lbmap.Backend4MapV3.DumpWithCallback(cbWrap),
		lbmap.Backend6MapV3.DumpWithCallback(cbWrap),
	)
}

// DeleteBackend implements lbmaps.
func (r *realLBMaps) DeleteBackend(key lbmap.BackendKey) error {
	_, err := key.Map().SilentDelete(key)
	return err
}

// DeleteService implements lbmaps.
func (r *realLBMaps) DeleteService(key lbmap.ServiceKey) error {
	_, err := key.Map().SilentDelete(key)
	return err
}

// DumpService4 implements lbmaps.
func (r *realLBMaps) DumpService(cb func(lbmap.ServiceKey, lbmap.ServiceValue)) error {
	cbWrap := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(lbmap.ServiceKey).ToHost()
		svcValue := value.(lbmap.ServiceValue).ToHost()
		cb(svcKey, svcValue)
	}
	return errors.Join(
		lbmap.Service4MapV2.DumpWithCallback(cbWrap),
		lbmap.Service6MapV2.DumpWithCallback(cbWrap),
	)
}

// UpdateBackend implements lbmaps.
func (r *realLBMaps) UpdateBackend(key lbmap.BackendKey, value lbmap.BackendValue) error {
	return key.Map().Update(key, value)
}

// UpdateService implements lbmaps.
func (r *realLBMaps) UpdateService(key lbmap.ServiceKey, value lbmap.ServiceValue) error {
	return key.Map().Update(key, value)
}

var _ lbmaps = &realLBMaps{}

type faultyLBMaps struct {
	impl lbmaps

	// 0.0 (never fail) ... 1.0 (always fail)
	failureProbability float32
}

// DeleteRevNat implements lbmaps.
func (f *faultyLBMaps) DeleteRevNat(key lbmap.RevNatKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteRevNat(key)
}

// DumpRevNat implements lbmaps.
func (f *faultyLBMaps) DumpRevNat(cb func(lbmap.RevNatKey, lbmap.RevNatValue)) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DumpRevNat(cb)
}

// UpdateRevNat implements lbmaps.
func (f *faultyLBMaps) UpdateRevNat(key lbmap.RevNatKey, value lbmap.RevNatValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateRevNat(key, value)
}

// DeleteBackend implements lbmaps.
func (f *faultyLBMaps) DeleteBackend(key lbmap.BackendKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteBackend(key)
}

// DeleteService implements lbmaps.
func (f *faultyLBMaps) DeleteService(key lbmap.ServiceKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteService(key)
}

// DumpBackend implements lbmaps.
func (f *faultyLBMaps) DumpBackend(cb func(lbmap.BackendKey, lbmap.BackendValue)) error {
	return f.impl.DumpBackend(cb)
}

// DumpService implements lbmaps.
func (f *faultyLBMaps) DumpService(cb func(lbmap.ServiceKey, lbmap.ServiceValue)) error {
	return f.impl.DumpService(cb)
}

// UpdateBackend implements lbmaps.
func (f *faultyLBMaps) UpdateBackend(key lbmap.BackendKey, value lbmap.BackendValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateBackend(key, value)
}

// UpdateService implements lbmaps.
func (f *faultyLBMaps) UpdateService(key lbmap.ServiceKey, value lbmap.ServiceValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateService(key, value)
}

func (f *faultyLBMaps) isFaulty() bool {
	// Float32() returns value between [0.0, 1.0).
	// We fail if the value is less than our probability [0.0, 1.0].
	return f.failureProbability > rand.Float32()
}

var errFaulty = errors.New("faulty")

var _ lbmaps = &faultyLBMaps{}

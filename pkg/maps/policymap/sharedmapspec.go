// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/spf13/viper"
)

const (
	PolicyOverlayMapName = "cilium_policy_o"
)

var (
	configuredPolicyMapMax int

	overlayPolicyMapOnce sync.Once
	overlayPolicyMap     *ebpf.Map
	overlayPolicyMapErr  error
)

func sharedPolicyLogger() *slog.Logger {
	return logging.DefaultSlogLogger.With(logfields.LogSubsys, "policymap")
}

// OverlayPolicyMap returns the overlay map keyed by endpoint ID.
// It first tries to load the existing pinned map, falling back to creating
// a new one if it doesn't exist.
func OverlayPolicyMap() (*ebpf.Map, error) {
	overlayPolicyMapOnce.Do(func() {
		// First, try to load the existing pinned map created by BPF loader
		overlayPolicyMap, overlayPolicyMapErr = ebpf.LoadRegisterMap(sharedPolicyLogger(), PolicyOverlayMapName)
		if overlayPolicyMapErr == nil {
			sharedPolicyLogger().Info("Loaded existing overlay policy map")
			return
		}

		// Map doesn't exist yet, create it
		sharedPolicyLogger().Debug("Overlay policy map not found, creating new one",
			logfields.Error, overlayPolicyMapErr)

		maxEntries := configuredPolicyMapMax
		if maxEntries == 0 {
			maxEntries = viper.GetInt("bpf-policy-map-max")
		}
		if maxEntries == 0 {
			maxEntries = defaults.PolicyMapEntries
		}
		overlayPolicyMap = ebpf.NewMap(sharedPolicyLogger(), &ebpf.MapSpec{
			Name:       PolicyOverlayMapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(uint32(0))),
			ValueSize:  uint32(unsafe.Sizeof(OverlayEntryBPF{})),
			MaxEntries: uint32(maxEntries),
			Flags:      0x01, // BPF_F_NO_PREALLOC - must match BPF side
			Pinning:    ebpf.PinByName,
		})
		overlayPolicyMapErr = nil
	})

	return overlayPolicyMap, overlayPolicyMapErr
}

var (
	updateOverlayPolicyEntry = func(epID uint16, overlay OverlayEntryBPF) error {
		m, err := OverlayPolicyMap()
		if err != nil {
			return err
		}
		if m == nil {
			return fmt.Errorf("overlay policy map unavailable")
		}
		epKey := uint32(epID)
		err = m.Update(&epKey, &overlay, 0)
		if err == nil {
			id := uint32(0)
			if info, err := m.Info(); err == nil {
				mid, _ := info.ID()
				id = uint32(mid)
			}
			sharedPolicyLogger().Info("Updated overlay policy entry",
				"endpointID", epID,
				"sharedRefCount", overlay.SharedRefCount,
				"mapID", id)
		}
		return err
	}

	deleteOverlayPolicyEntry = func(epID uint16) error {
		m, err := OverlayPolicyMap()
		if err != nil {
			return err
		}
		if m == nil {
			return fmt.Errorf("overlay policy map unavailable")
		}
		epKey := uint32(epID)
		err = m.Delete(&epKey)
		if err == nil {
			sharedPolicyLogger().Info("Deleted overlay policy entry",
				"endpointID", epID)
		}
		return err
	}
)

// InitSharedPolicyMaps eagerly creates the shared and overlay policy maps when
// the agent starts. This is done to ensure they are pinned and available even
// if no endpoints use them immediately.
func InitSharedPolicyMaps(maxEntries int) error {
	if !SharedManagerEnabled() {
		return nil
	}

	configuredPolicyMapMax = maxEntries

	overlay, err := OverlayPolicyMap()
	if err != nil {
		return err
	}
	if overlay == nil {
		return fmt.Errorf("overlay policy map unavailable")
	}

	// OpenOrCreate is safe to call even if map was loaded via LoadRegisterMap.
	// For loaded maps, it's a no-op. For new maps, it creates and pins.
	if err := overlay.OpenOrCreate(); err != nil {
		return fmt.Errorf("create %s: %w", PolicyOverlayMapName, err)
	}

	sharedPolicyLogger().Info("Initialized overlay policy map",
		"maxEntries", maxEntries)

	return nil
}

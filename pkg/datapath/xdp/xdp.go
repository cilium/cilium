// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdp

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/cell"
)

// Mode represents the mode to use when loading XDP programs.
// They are wrappers around the underlying mode names passed to
// the traffic control (tc) system in the kernel.
type Mode string

const (
	// ModeNative for loading progs with TCModeLinkDriver
	ModeNative Mode = "native"

	// ModeBestEffort for loading progs with TCModeLinkDriver,
	// falling back to TCModeLinkGeneric if unsupported by the
	// underlying device.
	ModeBestEffort Mode = "best-effort"

	// ModeGeneric for loading progs with TCModeLinkGeneric
	ModeGeneric Mode = "testing-only"

	// ModeDisabled for not having XDP enabled
	ModeDisabled Mode = "disabled"
)

// TCMode represents the name of an XDP mode from the perspective
// of the traffic control (tc) system in the kernel.
type TCMode string

const (

	// TCModeLinkDriver is the tc selector for native XDP
	TCModeLinkDriver TCMode = "xdpdrv"

	// TCModeLinkGeneric is the tc selector for generic XDP
	TCModeLinkGeneric TCMode = "xdpgeneric"

	// XDPModeLinkNone for not having XDP enabled
	TCModeLinkNone TCMode = TCMode(ModeDisabled)
)

// Config represents the materialized XDP configuration to be used,
// depending on its required use by other features.
type Config struct {
	mode Mode
}

type newConfigIn struct {
	cell.In

	Enablers []enabler `group:"request-xdp-mode"`
}

func newConfig(in newConfigIn) (Config, error) {
	cfg := Config{
		mode: ModeDisabled,
	}

	allValidators := []Validator{}

	for _, e := range in.Enablers {
		// Ensure the mode given in the enabler is valid.
		switch e.mode {
		case ModeBestEffort, ModeNative, ModeGeneric, ModeDisabled:
			break
		default:
			return cfg, fmt.Errorf("unknown xdp mode: %s", e.mode)
		}

		if e.mode != cfg.mode {
			allValidators = append(allValidators, e.validators...)

			// If an enabler requests a mode that we've already set,
			// then there's nothing to do.
			if cfg.mode == e.mode {
				continue
			}

			// If an enabler passes ModeDisabled, it becomes a no-op since
			// that's the default. If an enabler wishes to enforce that
			// XDP is disabled, it should use a verifier.
			if e.mode == ModeDisabled {
				continue
			}

			// Ensure ModeNative takes precedence over ModeBestEffort.
			// It doesn't make sense the other way around.
			if e.mode == ModeBestEffort && cfg.mode == ModeNative {
				continue
			} else if cfg.mode == ModeBestEffort && e.mode == ModeNative {
				cfg.mode = e.mode
				continue
			}

			// If a mode has been set and the enabler requests a conflicting
			// mode, then raise an error.
			if cfg.mode != ModeDisabled {
				return cfg, fmt.Errorf("XDP mode conflict: trying to set conflicting modes %s and %s",
					cfg.mode, e.mode)
			}

			cfg.mode = e.mode
		}
	}

	// Perform validation at the end, when the config is fully determined,
	// to ensure that processing order does not play a role in the validation.
	for _, v := range allValidators {
		if err := v(cfg.Mode(), cfg.TCMode()); err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

// Mode is the high-level XDP operating mode for Cilium.
func (cfg Config) Mode() Mode { return cfg.mode }

// TCMode, is the underlying XDP mode name for the traffic
// control (tc) system in the kernel.
func (cfg Config) TCMode() TCMode {
	switch cfg.mode {
	case ModeNative, ModeBestEffort:
		return TCModeLinkDriver
	case ModeGeneric:
		return TCModeLinkGeneric
	}

	return TCModeLinkNone
}

// Disabled returns true if XDP is disabled based on the configuration.
func (cfg Config) Disabled() bool { return cfg.mode == ModeDisabled }

// GetAttachFlags returns the XDP attach flags for the configured TCMode.
func (cfg Config) GetAttachFlags() link.XDPAttachFlags {
	switch cfg.mode {
	case ModeNative, ModeBestEffort:
		return link.XDPDriverMode
	case ModeGeneric:
		return link.XDPGenericMode
	}

	return 0
}

// EnablerOut allows requesting to enable a certain XDP operating mode.
type EnablerOut struct {
	cell.Out
	Enabler enabler `group:"request-xdp-mode"`
}

// NewEnabler returns an object to be injected through hive to request to
// enable a specific operating mode for XDP. Extra options are meaningful only
// when enable is set to true, and are ignored otherwise.
func NewEnabler(mode Mode, opts ...enablerOpt) EnablerOut {
	enabler := enabler{mode: mode}

	for _, opt := range opts {
		opt(&enabler)
	}

	return EnablerOut{Enabler: enabler}
}

type Validator func(Mode, TCMode) error

// WithValidator allows to register extra validation functions
// to assert that the configured XDP mode the one expected by
// the given feature.
func WithValidator(validator Validator) enablerOpt {
	return func(te *enabler) {
		te.validators = append(te.validators, validator)
	}
}

// WithEnforceXDPDisabled registers a validation function that
// returns an error if XDP is enabled.
func WithEnforceXDPDisabled(reason string) enablerOpt {
	return func(te *enabler) {
		te.validators = append(
			te.validators,
			func(m Mode, _ TCMode) error {
				if m != ModeDisabled {
					return fmt.Errorf("XDP config failed validation: XDP must be disabled because %s", reason)
				}

				return nil
			},
		)
	}
}

type enabler struct {
	mode       Mode
	validators []Validator
}

type enablerOpt func(*enabler)

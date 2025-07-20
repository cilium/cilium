// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdp

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/cell"
)

// AccelerationMode represents the mode to use when loading XDP programs.
// They are wrappers around the underlying mode names passed to
// the traffic control (tc) system in the kernel.
type AccelerationMode string

const (
	// AccelerationModeNative for loading progs with TCModeLinkDriver
	AccelerationModeNative AccelerationMode = "native"

	// AccelerationModeBestEffort for loading progs with TCModeLinkDriver,
	// falling back to TCModeLinkGeneric if unsupported by the
	// underlying device.
	AccelerationModeBestEffort AccelerationMode = "best-effort"

	// AccelerationModeGeneric for loading progs with TCModeLinkGeneric
	AccelerationModeGeneric AccelerationMode = "testing-only"

	// AccelerationModeDisabled for not having XDP enabled
	AccelerationModeDisabled AccelerationMode = "disabled"
)

// Mode represents the name of an XDP mode from the perspective
// of the kernel.
type Mode string

const (

	// ModeLinkDriver is the tc selector for native XDP
	ModeLinkDriver Mode = "xdpdrv"

	// ModeLinkGeneric is the tc selector for generic XDP
	ModeLinkGeneric Mode = "xdpgeneric"

	// XDPModeLinkNone for not having XDP enabled
	ModeLinkNone Mode = Mode(AccelerationModeDisabled)
)

// Config represents the materialized XDP configuration to be used,
// depending on its required use by other features.
type Config struct {
	mode AccelerationMode
}

type newConfigIn struct {
	cell.In

	Enablers []enabler `group:"request-xdp-mode"`
}

func newConfig(in newConfigIn) (Config, error) {
	cfg := Config{
		mode: AccelerationModeDisabled,
	}

	allValidators := []Validator{}

	for _, e := range in.Enablers {
		// Ensure the mode given in the enabler is valid.
		switch e.mode {
		case AccelerationModeBestEffort, AccelerationModeNative, AccelerationModeGeneric, AccelerationModeDisabled:
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
			if e.mode == AccelerationModeDisabled {
				continue
			}

			// Ensure ModeNative takes precedence over ModeBestEffort.
			// It doesn't make sense the other way around.
			if e.mode == AccelerationModeBestEffort && cfg.mode == AccelerationModeNative {
				continue
			} else if cfg.mode == AccelerationModeBestEffort && e.mode == AccelerationModeNative {
				cfg.mode = e.mode
				continue
			}

			// If a mode has been set and the enabler requests a conflicting
			// mode, then raise an error.
			if cfg.mode != AccelerationModeDisabled {
				return cfg, fmt.Errorf("XDP mode conflict: trying to set conflicting modes %s and %s",
					cfg.mode, e.mode)
			}

			cfg.mode = e.mode
		}
	}

	// Perform validation at the end, when the config is fully determined,
	// to ensure that processing order does not play a role in the validation.
	for _, v := range allValidators {
		if err := v(cfg.AccelerationMode(), cfg.Mode()); err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

// AccelerationMode is the high-level XDP operating mode for Cilium.
func (cfg Config) AccelerationMode() AccelerationMode { return cfg.mode }

// Mode, is the underlying mode name that is used for loading the XDP
// program into the kernel.
func (cfg Config) Mode() Mode {
	switch cfg.mode {
	case AccelerationModeNative, AccelerationModeBestEffort:
		return ModeLinkDriver
	case AccelerationModeGeneric:
		return ModeLinkGeneric
	}

	return ModeLinkNone
}

// Disabled returns true if XDP is disabled based on the configuration.
func (cfg Config) Disabled() bool { return cfg.mode == AccelerationModeDisabled }

// GetAttachFlags returns the XDP attach flags for the configured TCMode.
func (cfg Config) GetAttachFlags() link.XDPAttachFlags {
	switch cfg.mode {
	case AccelerationModeNative, AccelerationModeBestEffort:
		return link.XDPDriverMode
	case AccelerationModeGeneric:
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
func NewEnabler(mode AccelerationMode, opts ...enablerOpt) EnablerOut {
	enabler := enabler{mode: mode}

	for _, opt := range opts {
		opt(&enabler)
	}

	return EnablerOut{Enabler: enabler}
}

type Validator func(AccelerationMode, Mode) error

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
			func(m AccelerationMode, _ Mode) error {
				if m != AccelerationModeDisabled {
					return fmt.Errorf("XDP config failed validation: XDP must be disabled because %s", reason)
				}

				return nil
			},
		)
	}
}

type enabler struct {
	mode       AccelerationMode
	validators []Validator
}

type enablerOpt func(*enabler)

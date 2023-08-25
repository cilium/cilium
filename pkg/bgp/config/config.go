// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package config provides BGP configuration logic.
package config

import (
	"fmt"
	"io"

	metallbcfg "go.universe.tf/metallb/pkg/config"

	"github.com/cilium/cilium/pkg/safeio"
)

// Parse parses and validates the BGP configuration for use with MetalLB. It
// expects the string to be in YAML or JSON form.
func Parse(r io.Reader) (*metallbcfg.Config, error) {
	buf, err := safeio.ReadAllLimit(r, safeio.MB)
	if err != nil {
		return nil, fmt.Errorf("failed to read MetalLB config: %w", err)
	}
	config, err := metallbcfg.Parse(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MetalLB config: %w", err)
	}
	return config, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package client

import (
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
)

func TestCell_WithoutServerAddr(t *testing.T) {
	h := hive.New(
		Cell,
	)
	hive.AddConfigOverride(
		h,
		func(cfg *Config) {
			cfg.ServerAddr = ""
		})

	// Missing ServerAddr disables the feature.
	if err := h.Populate(hivetest.Logger(t)); err != nil {
		t.Fatalf("Failed to populate: %s", err)
	}
}

func TestCell_WithServerAddr(t *testing.T) {
	h := hive.New(
		Cell,
	)
	hive.AddConfigOverride(
		h,
		func(cfg *Config) {
			cfg.ServerAddr = "127.0.0.1:1234"
		})

	// Providing ServerAddr is sufficient configuration.
	if err := h.Populate(hivetest.Logger(t)); err != nil {
		t.Fatalf("Failed to populate: %s", err)
	}
}

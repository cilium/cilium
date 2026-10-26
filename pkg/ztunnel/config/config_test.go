// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/require"
)

func TestSpiffeTrustDomain(t *testing.T) {
	for _, tt := range []struct {
		domain  string
		invalid bool
	}{
		{domain: ""},
		{domain: "spiffe.cilium"},
		{domain: "custom.example"},
		{domain: "invalid/domain", invalid: true},
		{domain: "spiffe://custom.example", invalid: true},
	} {
		t.Run(tt.domain, func(t *testing.T) {
			var actual Config
			h := hive.New(
				cell.Config(DefaultConfig),
				cell.Invoke(func(cfg Config) { actual = cfg }),
			)
			h.Viper().Set("ztunnel-spiffe-trust-domain", tt.domain)
			require.NoError(t, h.Populate(slog.New(slog.DiscardHandler)))
			require.Equal(t, tt.domain, actual.SpiffeTrustDomain)
			if tt.invalid {
				require.ErrorContains(t, actual.Validate(), "invalid ztunnel SPIFFE trust domain")
			} else {
				require.NoError(t, actual.Validate())
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
)

func TestConfig(t *testing.T) {
	var tests = []struct {
		name     string
		override func(*config)
		expected Config
	}{
		{
			name: "default",
			expected: Config{
				CNIChainingMode: "none",
				CNILogFile:      "/var/run/cilium/cilium-cni.log",
			},
		},
		{
			name:     "aws-cni chaining mode",
			override: func(c *config) { c.CNIChainingMode = "aws-cni" },
			expected: Config{
				CNIChainingMode:    "aws-cni",
				CNIChainingTarget:  "aws-cni",
				CNIExternalRouting: true,
				CNILogFile:         "/var/run/cilium/cilium-cni.log",
			},
		},
		{
			name: "generic-veth chaining mode",
			override: func(c *config) {
				c.CNIChainingMode, c.CNIChainingTarget = "", "foo"
			},
			expected: Config{
				CNIChainingMode:   "generic-veth",
				CNIChainingTarget: "foo",
				CNILogFile:        "/var/run/cilium/cilium-cni.log",
			},
		},
		{
			name:     "empty chaining mode",
			override: func(c *config) { c.CNIChainingMode = "" },
			expected: Config{
				CNIChainingMode: "none",
				CNILogFile:      "/var/run/cilium/cilium-cni.log",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				got Config

				h = hive.New(
					Cell,

					cell.Invoke(
						func(cfg Config) {
							got = cfg
						},
					),
				)
			)

			if tt.override != nil {
				hive.AddConfigOverride(h, tt.override)
			}

			require.NoError(t, h.Populate(hivetest.Logger(t)), "hive.Populate")
			require.Equal(t, tt.expected, got)
		})
	}
}

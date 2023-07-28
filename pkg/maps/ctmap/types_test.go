// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
)

func TestMapKey(t *testing.T) {
	for mapType := mapType(0); mapType < mapTypeMax; mapType++ {
		assert.NotNil(t, mapType.key())
	}

	assert.Panics(t, func() { mapType(-1).key() })
	assert.Panics(t, func() { mapTypeMax.key() })
}

func TestMapBPFDefine(t *testing.T) {
	for mapType := mapType(0); mapType < mapTypeMax; mapType++ {
		if mapType.isIPv6() {
			assert.Contains(t, mapType.bpfDefine(), "6")
		}
		if mapType.isIPv4() {
			assert.Contains(t, mapType.bpfDefine(), "4")
		}

		if mapType.isTCP() {
			assert.Contains(t, mapType.bpfDefine(), "TCP")
		} else {
			assert.Contains(t, mapType.bpfDefine(), "ANY")
		}
	}

	assert.Panics(t, func() { mapType(-1).bpfDefine() })
	assert.Panics(t, func() { mapTypeMax.bpfDefine() })
}

func TestMaxEntries(t *testing.T) {
	tests := []struct {
		name       string
		tcp, any   int
		etcp, eany int
	}{
		{
			name: "defaults",
			etcp: option.CTMapEntriesGlobalTCPDefault,
			eany: option.CTMapEntriesGlobalAnyDefault,
		},
		{
			name: "configured",
			tcp:  0x12345,
			etcp: 0x12345,
			any:  0x67890,
			eany: 0x67890,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.CTMapEntriesGlobalTCP = tt.tcp
			option.Config.CTMapEntriesGlobalAny = tt.any

			for mapType := mapType(0); mapType < mapTypeMax; mapType++ {
				if mapType.isLocal() {
					assert.Equal(t, mapNumEntriesLocal, mapType.maxEntries())
				}

				if mapType.isGlobal() {
					if mapType.isTCP() {
						assert.Equal(t, tt.etcp, mapType.maxEntries())
					} else {
						assert.Equal(t, tt.eany, mapType.maxEntries())
					}
				}
			}

			assert.Panics(t, func() { mapType(-1).maxEntries() })
			assert.Panics(t, func() { mapTypeMax.maxEntries() })
		})
	}
}

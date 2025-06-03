// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type MaglevSuite struct {
}

func setupMaglevSuite(tb testing.TB) *MaglevSuite {
	testutils.PrivilegedTest(tb)

	s := &MaglevSuite{}

	// Otherwise opening the map might fail with EPERM
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)

	Init(nil, InitParams{
		IPv4: option.Config.EnableIPv4,
		IPv6: option.Config.EnableIPv6,

		ServiceMapMaxEntries: DefaultMaxEntries,
		RevNatMapMaxEntries:  DefaultMaxEntries,
		MaglevMapMaxEntries:  DefaultMaxEntries,
	})

	return s
}

func TestInitMaps(t *testing.T) {
	setupMaglevSuite(t)
	logger := hivetest.Logger(t)

	maglevTableSize := uint(251)
	err := InitMaglevMaps(logger, true, false, uint32(maglevTableSize))
	require.NoError(t, err)

	maglevTableSize = 509
	// M mismatch, so the map should be removed
	deleted, err := deleteMapIfMNotMatch(logger, MaglevOuter4MapName, uint32(maglevTableSize))
	require.NoError(t, err)
	require.True(t, deleted)

	// M is the same, but no entries, so the map should be removed too
	err = InitMaglevMaps(logger, true, false, uint32(maglevTableSize))
	require.NoError(t, err)
	deleted, err = deleteMapIfMNotMatch(logger, MaglevOuter4MapName, uint32(maglevTableSize))
	require.NoError(t, err)
	require.True(t, deleted)

	// Now insert the entry, so that the map should not be removed
	err = InitMaglevMaps(logger, true, false, uint32(maglevTableSize))
	require.NoError(t, err)
	cfg, err := maglev.UserConfig{
		TableSize: maglevTableSize,
		HashSeed:  maglev.DefaultHashSeed,
	}.ToConfig()
	require.NoError(t, err, "ToConfig")
	ml := maglev.New(cfg, hivetest.Lifecycle(t))
	lbm := New(logger, loadbalancer.DefaultConfig, ml)
	params := &datapathTypes.UpsertServiceParams{
		ID:   1,
		IP:   net.ParseIP("1.1.1.1"),
		Port: 8080,
		ActiveBackends: map[string]*loadbalancer.LegacyBackend{"backend-1": {
			ID:     1,
			Weight: 1,
		}},
		Type:      loadbalancer.SVCTypeNodePort,
		UseMaglev: true,
	}
	err = lbm.UpsertService(params)
	require.NoError(t, err)
	deleted, err = deleteMapIfMNotMatch(logger, MaglevOuter4MapName, uint32(maglevTableSize))
	require.NoError(t, err)
	require.False(t, deleted)
}

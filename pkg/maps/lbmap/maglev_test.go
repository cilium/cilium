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
	prevNodePortAlg string
}

func setupMaglevSuite(tb testing.TB) *MaglevSuite {
	testutils.PrivilegedTest(tb)

	s := &MaglevSuite{}

	s.prevNodePortAlg = option.Config.NodePortAlg

	// Otherwise opening the map might fail with EPERM
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)

	option.Config.LBMapEntries = DefaultMaxEntries
	option.Config.NodePortAlg = option.NodePortAlgMaglev

	Init(InitParams{
		IPv4: option.Config.EnableIPv4,
		IPv6: option.Config.EnableIPv6,

		ServiceMapMaxEntries: option.Config.LBMapEntries,
		RevNatMapMaxEntries:  option.Config.LBMapEntries,
		MaglevMapMaxEntries:  option.Config.LBMapEntries,
	})

	tb.Cleanup(func() {
		option.Config.NodePortAlg = s.prevNodePortAlg
	})

	return s
}

func TestInitMaps(t *testing.T) {
	setupMaglevSuite(t)

	maglevTableSize := uint(251)
	err := InitMaglevMaps(true, false, uint32(maglevTableSize))
	require.NoError(t, err)

	maglevTableSize = 509
	// M mismatch, so the map should be removed
	deleted, err := deleteMapIfMNotMatch(MaglevOuter4MapName, uint32(maglevTableSize))
	require.NoError(t, err)
	require.True(t, deleted)

	// M is the same, but no entries, so the map should be removed too
	err = InitMaglevMaps(true, false, uint32(maglevTableSize))
	require.NoError(t, err)
	deleted, err = deleteMapIfMNotMatch(MaglevOuter4MapName, uint32(maglevTableSize))
	require.NoError(t, err)
	require.True(t, deleted)

	// Now insert the entry, so that the map should not be removed
	err = InitMaglevMaps(true, false, uint32(maglevTableSize))
	require.NoError(t, err)
	ml, err := maglev.New(maglev.Config{
		MaglevTableSize: maglevTableSize,
		MaglevHashSeed:  maglev.DefaultHashSeed,
	}, hivetest.Lifecycle(t))
	require.NoError(t, err, "maglev.New")
	lbm := New(ml)
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
	deleted, err = deleteMapIfMNotMatch(MaglevOuter4MapName, uint32(maglevTableSize))
	require.NoError(t, err)
	require.False(t, deleted)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
)

type dummyStateKey struct {
	_ uint32
}

func (k *dummyStateKey) New() bpf.MapKey {
	return &dummyStateKey{}
}

func (k *dummyStateKey) String() string {
	return ""
}

type dummyStateValue struct {
	_ uint32
}

func (v *dummyStateValue) New() bpf.MapValue {
	return &dummyStateValue{}
}

func (v *dummyStateValue) String() string {
	return ""
}

func TestStateMapsHive(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	// Dummy maps. Name should be matched to the real one, but other fields
	// are not important.
	m4 := bpf.NewMap(
		stateMapName4,
		ebpf.Hash,
		&dummyStateKey{},
		&dummyStateValue{},
		1,
		0,
	)
	m6 := bpf.NewMap(
		stateMapName6,
		ebpf.Hash,
		&dummyStateKey{},
		&dummyStateValue{},
		1,
		0,
	)

	// Create maps
	require.NoError(t, m4.Create())
	require.NoError(t, m6.Create())

	// Ensure maps are pinned
	require.FileExists(t, bpf.MapPath(logger, stateMapName4))
	require.FileExists(t, bpf.MapPath(logger, stateMapName6))

	t.Cleanup(func() {
		// Ensure they are unpinned even if the test fails
		m4.Unpin()
		m6.Unpin()
	})

	hive := hive.New(
		cell.Invoke(cleanupStateMap),
	)
	require.NoError(t, hive.Start(logger, context.TODO()))
	t.Cleanup(func() {
		require.NoError(t, hive.Stop(logger, context.TODO()))
	})

	// State maps should be deleted after Invoke
	require.NoFileExists(t, bpf.MapPath(logger, stateMapName4))
	require.NoFileExists(t, bpf.MapPath(logger, stateMapName6))
}

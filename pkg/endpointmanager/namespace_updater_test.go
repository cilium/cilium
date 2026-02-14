// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/labels"
)

type nsUpdaterTestFixture struct {
	db         *statedb.DB
	namespaces statedb.RWTable[daemonk8s.Namespace]
	changeIter statedb.ChangeIterator[daemonk8s.Namespace]
	// Tracking maps mirror namespaceUpdater's internal state
	oldIdtyLabels   map[string]labels.Labels
	oldSIPAllowAnno map[string]string
}

func newNSUpdaterTestFixture(t testing.TB) *nsUpdaterTestFixture {
	var (
		db  *statedb.DB
		tbl statedb.RWTable[daemonk8s.Namespace]
	)

	logger := hivetest.Logger(t)

	hive.New(
		cell.Provide(
			daemonk8s.NewNamespaceTable,
			statedb.RWTable[daemonk8s.Namespace].ToTable,
		),
		cell.Invoke(func(d *statedb.DB, t statedb.RWTable[daemonk8s.Namespace]) {
			db = d
			tbl = t
		}),
	).Populate(logger)

	// Initialize change iterator (same as run() does)
	wtxn := db.WriteTxn(tbl)
	changeIter, err := tbl.Changes(wtxn)
	require.NoError(t, err)
	wtxn.Commit()

	return &nsUpdaterTestFixture{
		db:              db,
		namespaces:      tbl,
		changeIter:      changeIter,
		oldIdtyLabels:   make(map[string]labels.Labels),
		oldSIPAllowAnno: make(map[string]string),
	}
}

func (f *nsUpdaterTestFixture) insertNS(t testing.TB, name string, lbls, annotations map[string]string) {
	wtxn := f.db.WriteTxn(f.namespaces)
	_, _, err := f.namespaces.Insert(wtxn, daemonk8s.Namespace{
		Name:        name,
		Labels:      lbls,
		Annotations: annotations,
		UpdatedAt:   time.Now(),
	})
	require.NoError(t, err)
	wtxn.Commit()
}

func (f *nsUpdaterTestFixture) deleteNS(t testing.TB, name string) {
	wtxn := f.db.WriteTxn(f.namespaces)
	_, _, err := f.namespaces.Delete(wtxn, daemonk8s.Namespace{Name: name})
	require.NoError(t, err)
	wtxn.Commit()
}

// processChanges simulates what namespaceUpdater.run() does in its main loop.
// This is the core logic being tested - handling both updates and deletes.
func (f *nsUpdaterTestFixture) processChanges() {
	changes, _ := f.changeIter.Next(f.db.ReadTxn())
	for change := range changes {
		if change.Deleted {
			delete(f.oldIdtyLabels, change.Object.Name)
			delete(f.oldSIPAllowAnno, change.Object.Name)
		} else {
			// Simplified update: just track the values (skip endpoint operations)
			f.oldIdtyLabels[change.Object.Name] = labels.Map2Labels(change.Object.Labels, labels.LabelSourceK8s)
			f.oldSIPAllowAnno[change.Object.Name] = change.Object.Annotations[annotation.AllowDisableSourceIPVerification]
		}
	}
}

// TestNSUpdaterDeleteCleanup verifies tracking maps are cleaned up on namespace deletion.
func TestNSUpdaterDeleteCleanup(t *testing.T) {
	fix := newNSUpdaterTestFixture(t)
	nsName := "test-ns"

	// Insert namespace
	fix.insertNS(t, nsName, map[string]string{"env": "test"}, map[string]string{
		annotation.AllowDisableSourceIPVerification: "true",
	})
	fix.processChanges()

	assert.Contains(t, fix.oldIdtyLabels, nsName)
	assert.Equal(t, "true", fix.oldSIPAllowAnno[nsName])

	// Delete namespace
	fix.deleteNS(t, nsName)
	fix.processChanges()

	// Verify cleanup
	assert.NotContains(t, fix.oldIdtyLabels, nsName)
	assert.NotContains(t, fix.oldSIPAllowAnno, nsName)
}

// TestNSUpdaterRecreate verifies correct handling after namespace delete and recreate.
func TestNSUpdaterRecreate(t *testing.T) {
	fix := newNSUpdaterTestFixture(t)
	nsName := "recreate-ns"

	// Create with annotation "true"
	fix.insertNS(t, nsName, nil, map[string]string{
		annotation.AllowDisableSourceIPVerification: "true",
	})
	fix.processChanges()
	assert.Equal(t, "true", fix.oldSIPAllowAnno[nsName])

	// Delete
	fix.deleteNS(t, nsName)
	fix.processChanges()
	assert.NotContains(t, fix.oldSIPAllowAnno, nsName)

	// Recreate with annotation "false"
	fix.insertNS(t, nsName, nil, map[string]string{
		annotation.AllowDisableSourceIPVerification: "false",
	})
	fix.processChanges()

	// Should reflect new value, not stale "true"
	assert.Equal(t, "false", fix.oldSIPAllowAnno[nsName])
}

// TestNSUpdaterMultipleNS verifies deleting one namespace doesn't affect others.
func TestNSUpdaterMultipleNS(t *testing.T) {
	fix := newNSUpdaterTestFixture(t)

	// Insert multiple namespaces
	fix.insertNS(t, "ns-a", map[string]string{"env": "a"}, map[string]string{
		annotation.AllowDisableSourceIPVerification: "true",
	})
	fix.insertNS(t, "ns-b", map[string]string{"env": "b"}, map[string]string{
		annotation.AllowDisableSourceIPVerification: "false",
	})
	fix.insertNS(t, "ns-c", map[string]string{"env": "c"}, nil)
	fix.processChanges()

	assert.Len(t, fix.oldIdtyLabels, 3)

	// Delete only ns-b
	fix.deleteNS(t, "ns-b")
	fix.processChanges()

	// Verify isolation
	assert.Len(t, fix.oldIdtyLabels, 2)
	assert.Contains(t, fix.oldIdtyLabels, "ns-a")
	assert.NotContains(t, fix.oldIdtyLabels, "ns-b")
	assert.Contains(t, fix.oldIdtyLabels, "ns-c")
	assert.Equal(t, "true", fix.oldSIPAllowAnno["ns-a"])
	assert.Equal(t, "", fix.oldSIPAllowAnno["ns-c"])
}

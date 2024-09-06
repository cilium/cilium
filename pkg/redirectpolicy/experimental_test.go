// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"testing"
	"text/tabwriter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/time"
)

func TestLRPController(t *testing.T) {
	lrpFiles := []string{
		"testdata/lrp_addr.yaml",
		"testdata/lrp_svc.yaml",
	}
	podFiles := []string{
		"testdata/pod.yaml",
	}
	lbFiles := []string{
		"testdata/endpointslice.yaml",
		"testdata/endpointslice2.yaml",
		"testdata/service.yaml",
		"testdata/service2.yaml",
	}

	runLRPTest(
		t,
		lrpFiles,
		podFiles,
		lbFiles,
	)
}

func runLRPTest(t *testing.T, lrpFiles, podFiles, lbFiles []string) {
	lrpLW, podLW := testutils.NewFakeListerWatcher(), testutils.NewFakeListerWatcher()
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	var (
		db       *statedb.DB
		writer   *experimental.Writer
		lrpTable statedb.Table[*LRPConfig]
	)

	hive := hive.New(
		experimental.TestCell,
		experimental.TestInputsFromFiles(t, lbFiles),

		cell.Module("test", "test",
			experimentalCells,

			supply(lrpIsEnabled(true)),
			supply(podListerWatcher(podLW)),
			supply(lrpListerWatcher(lrpLW)),

			cell.Invoke(
				func(db_ *statedb.DB, w *experimental.Writer, lrpTable_ statedb.Table[*LRPConfig]) {
					db = db_
					writer = w
					lrpTable = lrpTable_
				},
			),
		),
	)

	dumpTables := func() []byte {
		var tableBuf bytes.Buffer
		writer.DebugDump(db.ReadTxn(), &tableBuf)
		tw := tabwriter.NewWriter(&tableBuf, 5, 0, 3, ' ', 0)
		fmt.Fprintln(tw, "\n--- LRPs ---")
		fmt.Fprintln(tw, strings.Join((*LRPConfig)(nil).TableHeader(), "\t"))
		iter := lrpTable.All(db.ReadTxn())
		for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
			fmt.Fprintln(tw, strings.Join(svc.TableRow(), "\t"))
		}
		tw.Flush()
		return experimental.SanitizeTableDump(tableBuf.Bytes())
	}

	assertTables := func(suffix string) {
		expectedFile := "expected" + suffix + ".tables"
		actualFile := "actual" + suffix + ".tables"

		var expectedTables []byte
		if expectedData, err := os.ReadFile(path.Join("testdata", expectedFile)); err == nil {
			expectedTables = expectedData
		}
		var lastActual []byte
		if !assert.Eventually(
			t,
			func() bool {
				lastActual = dumpTables()
				return bytes.Equal(lastActual, expectedTables)
			},
			time.Second,
			10*time.Millisecond) {
			os.WriteFile(path.Join("testdata", actualFile), lastActual, 0644)
			logDiff(t, path.Join("testdata", actualFile), path.Join("testdata", expectedFile))
			t.Error("Mismatching tables")
		}
	}

	// --------------------------

	require.NoError(t, hive.Start(log, context.TODO()), "Start")
	t.Cleanup(func() {
		assert.NoError(t, hive.Stop(log, context.TODO()), "Stop")
	})

	for _, f := range podFiles {
		require.NoError(
			t,
			podLW.UpsertFromFile(f),
			"Upsert "+f,
		)
	}
	assertTables("_before")

	for _, f := range lrpFiles {
		require.NoError(
			t,
			lrpLW.UpsertFromFile(f),
			"Upsert "+f,
		)
	}

	assertTables("")

	for _, f := range lrpFiles {
		require.NoError(
			t,
			lrpLW.DeleteFromFile(f),
			"Delete "+f,
		)
	}

	assertTables("_after")
}

func supply[T any](x T) cell.Cell {
	return cell.Provide(func() T { return x })
}

func logDiff(t *testing.T, fileA, fileB string) {
	t.Helper()

	contentsA, err := os.ReadFile(fileA)
	require.NoError(t, err)
	contentsB, _ := os.ReadFile(fileB)

	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(contentsA)),
		B:        difflib.SplitLines(string(contentsB)),
		FromFile: fileA,
		ToFile:   fileB,
		Context:  2,
	}
	text, _ := difflib.GetUnifiedDiffString(diff)
	if len(text) > 0 {
		t.Logf("\n%s", text)
	}
}

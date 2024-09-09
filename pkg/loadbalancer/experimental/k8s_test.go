// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"bytes"
	"context"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/cilium/stream"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	slimDecoder k8sRuntime.Decoder
)

func init() {
	slimScheme := k8sRuntime.NewScheme()
	slim_fake.AddToScheme(slimScheme)
	slimScheme.AddKnownTypes(slim_corev1.SchemeGroupVersion, &metav1.List{})
	slimDecoder = serializer.NewCodecFactory(slimScheme).UniversalDeserializer()
}

func decodeObject[Obj k8sRuntime.Object](t *testing.T, file string) Obj {
	bytes, err := os.ReadFile(file)
	require.NoError(t, err, "ReadFile(%s)", file)
	obj, _, err := slimDecoder.Decode(bytes, nil, nil)
	require.NoError(t, err, "Decode(%s)", file)
	return obj.(Obj)
}

func readObjects[Obj k8sRuntime.Object](t *testing.T, dataDir string, prefix string) (out []Obj) {
	ents, err := os.ReadDir(dataDir)
	require.NoError(t, err, "ReadDir(%s)", dataDir)

	for _, ent := range ents {
		if strings.HasPrefix(ent.Name(), prefix) && strings.HasSuffix(ent.Name(), ".yaml") {
			out = append(out, decodeObject[Obj](t, path.Join(dataDir, ent.Name())))
		}
	}
	return
}

func upsertEvent[Obj k8sRuntime.Object](obj Obj) resource.Event[Obj] {
	return resource.Event[Obj]{
		Object: obj,
		Key:    resource.NewKey(obj),
		Kind:   resource.Upsert,
		Done:   func(error) {},
	}
}

func deleteEvent[Obj k8sRuntime.Object](obj Obj) resource.Event[Obj] {
	return resource.Event[Obj]{
		Object: obj,
		Key:    resource.NewKey(obj),
		Kind:   resource.Delete,
		Done:   func(error) {},
	}
}

func TestIntegrationK8s(t *testing.T) {
	t.Parallel()

	dirs, err := os.ReadDir("testdata")
	require.NoError(t, err, "ReadDir(testdata)")

	for _, ent := range dirs {
		if !ent.IsDir() {
			continue
		}

		testDataPath := path.Join("testdata", ent.Name())

		// Skip directories that don't have any yaml files. This avoids issues when
		// switching branches and having leftover "actual" files.
		if !hasYamlFiles(testDataPath) {
			continue
		}
		t.Run(ent.Name(), func(t *testing.T) {
			testIntegrationK8s(t, testDataPath)
		})
	}
}

func testIntegrationK8s(t *testing.T, testDataPath string) {
	//  As we're using k8s.Endpoints we need to set this to ask ParseEndpoint*
	// to handle the termination state. Eventually this should migrate to the
	// package for the k8s data source.
	option.Config.EnableK8sTerminatingEndpoint = true

	extConfig := externalConfig{
		ExternalClusterIP:     false,
		EnableSessionAffinity: true,
		NodePortMin:           option.NodePortMinDefault,
		NodePortMax:           option.NodePortMaxDefault,
	}

	log := hivetest.Logger(t)

	var maps lbmaps
	if testutils.IsPrivileged() {
		maps = &realLBMaps{
			pinned: false,
			cfg: LBMapsConfig{
				MaxSockRevNatMapEntries:  1000,
				ServiceMapMaxEntries:     1000,
				BackendMapMaxEntries:     1000,
				RevNatMapMaxEntries:      1000,
				AffinityMapMaxEntries:    1000,
				SourceRangeMapMaxEntries: 1000,
				MaglevMapMaxEntries:      1000,
			},
		}
	} else {
		maps = newFakeLBMaps()
	}

	services := make(chan resource.Event[*slim_corev1.Service], 1)
	services <- resource.Event[*slim_corev1.Service]{
		Kind: resource.Sync,
		Done: func(error) {},
	}
	pods := make(chan resource.Event[*slim_corev1.Pod], 1)
	pods <- resource.Event[*slim_corev1.Pod]{
		Kind: resource.Sync,
		Done: func(error) {},
	}

	endpoints := make(chan resource.Event[*k8s.Endpoints], 1)
	endpoints <- resource.Event[*k8s.Endpoints]{
		Kind: resource.Sync,
		Done: func(error) {},
	}

	var (
		writer *Writer
		db     *statedb.DB
		bo     *bpfOps
		rec    reconciler.Reconciler[*Frontend]
	)

	h := hive.New(
		cell.Module(
			"loadbalancer-test",
			"Test module",

			cell.Provide(
				func() Config {
					return Config{
						EnableExperimentalLB: true,
						RetryBackoffMin:      time.Millisecond,
						RetryBackoffMax:      time.Millisecond,
					}
				},
				func() externalConfig { return extConfig },
			),

			cell.Provide(func() streamsOut {
				return streamsOut{
					ServicesStream:  stream.FromChannel(services),
					EndpointsStream: stream.FromChannel(endpoints),
					PodsStream:      stream.FromChannel(pods),
				}
			}),

			cell.Provide(
				func(lc cell.Lifecycle) lbmaps {
					if rm, ok := maps.(*realLBMaps); ok {
						lc.Append(rm)
					}
					return &faultyLBMaps{
						impl:               maps,
						failureProbability: 0.1, // 10% chance of failure.
					}
				},
			),

			cell.Invoke(func(db_ *statedb.DB, w *Writer, bo_ *bpfOps, rec_ reconciler.Reconciler[*Frontend]) {
				db = db_
				writer = w
				bo = bo_
				rec = rec_
			}),

			// Provides [Writer] API and the load-balancing tables.
			TablesCell,

			// Reflects Kubernetes services and endpoints to the load-balancing tables
			// using the [Writer].
			ReflectorCell,

			// Reconcile tables to BPF maps
			ReconcilerCell,

			cell.Provide(
				tables.NewNodeAddressTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
			),
			cell.Invoke(func(db *statedb.DB, nodeAddrs statedb.RWTable[tables.NodeAddress]) {
				db.RegisterTable(nodeAddrs)
				txn := db.WriteTxn(nodeAddrs)

				for _, addr := range nodePortAddrs {
					nodeAddrs.Insert(
						txn,
						tables.NodeAddress{
							Addr:       addr,
							NodePort:   true,
							Primary:    true,
							DeviceName: "eth0",
						},
					)
					nodeAddrs.Insert(
						txn,
						tables.NodeAddress{
							Addr:       addr,
							NodePort:   true,
							Primary:    true,
							DeviceName: "eth0",
						},
					)
				}
				txn.Commit()

			}),
		),
	)

	require.NoError(t, h.Start(log, context.TODO()))
	t.Cleanup(func() {
		assert.NoError(t, h.Stop(log, context.TODO()))
	})

	//
	// Feed in all the test objects
	//
	// TODO: allow multiple stages in the style of test/controlplane.

	for _, obj := range readObjects[*slim_corev1.Service](t, testDataPath, "service") {
		services <- upsertEvent(obj)
	}

	for _, obj := range readObjects[*slim_corev1.Pod](t, testDataPath, "pod") {
		pods <- upsertEvent(obj)
	}

	for _, obj := range readObjects[*slim_discovery_v1.EndpointSlice](t, testDataPath, "endpointslice") {
		endpoints <- upsertEvent(k8s.ParseEndpointSliceV1(obj))
	}

	if !assert.Eventually(
		t,
		func() bool {
			return checkTablesAndMaps(db, writer, maps, testDataPath)
		},
		5*time.Second,
		10*time.Millisecond,
		"Mismatching tables and/or BPF maps",
	) {
		logDiff(t, path.Join(testDataPath, "actual.tables"), path.Join(testDataPath, "expected.tables"))
		logDiff(t, path.Join(testDataPath, "actual.maps"), path.Join(testDataPath, "expected.maps"))
		t.FailNow()
	}

	// Force pruning and check again to make sure pruning did not mess things up.
	rec.Prune()

	if !assert.Eventually(
		t,
		func() bool {
			ok := checkTablesAndMaps(db, writer, maps, testDataPath)
			if !ok {
				// Keep re-pruning since a fault may have been injected.
				// FIXME: Reconciler likely should retry pruning automatically!
				rec.Prune()
			}
			return ok
		},
		5*time.Second,
		10*time.Millisecond,
		"Mismatching tables and/or BPF maps AFTER PRUNING",
	) {
		logDiff(t, path.Join(testDataPath, "actual.tables"), path.Join(testDataPath, "expected.tables"))
		logDiff(t, path.Join(testDataPath, "actual.maps"), path.Join(testDataPath, "expected.maps"))
		t.FailNow()
	}

	// Snapshot the contents of the maps to test out pruning of state has been cleared.
	snapshot := snapshotMaps(maps)

	//
	// Feed in deletions of all objects.
	//
	for _, obj := range readObjects[*slim_corev1.Service](t, testDataPath, "service") {
		services <- deleteEvent(obj)
	}

	for _, obj := range readObjects[*slim_corev1.Pod](t, testDataPath, "pod") {
		pods <- deleteEvent(obj)
	}

	for _, obj := range readObjects[*slim_discovery_v1.EndpointSlice](t, testDataPath, "endpointslice") {
		endpoints <- deleteEvent(k8s.ParseEndpointSliceV1(obj))
	}

	// The reconciler should eventually clean up all the maps.
	var lastDump []mapDump
	if !assert.Eventually(
		t,
		func() bool {
			lastDump = dump(maps, frontendAddrs[0], true)
			return len(lastDump) == 0
		},
		5*time.Second,
		50*time.Millisecond) {
		t.Fatalf("Expected BPF maps to be empty, instead they contain: %v", lastDump)
	}

	// The tables should now all be empty.
	require.Zero(t, writer.Frontends().NumObjects(db.ReadTxn()))
	require.Zero(t, writer.Backends().NumObjects(db.ReadTxn()))
	require.Zero(t, writer.Services().NumObjects(db.ReadTxn()))

	// Reconciler state should be clean
	assert.Len(t, bo.backendReferences, 0)
	assert.Len(t, bo.backendStates, 0)
	assert.Len(t, bo.nodePortAddrs, 0)
	assert.Len(t, bo.serviceIDAlloc.entities, 0)
	assert.Len(t, bo.backendIDAlloc.entities, 0)

	// Test passed, remove the actual files in order not to leave them around.
	os.Remove(path.Join(testDataPath, "actual.tables"))
	os.Remove(path.Join(testDataPath, "actual.maps"))

	// Test pruning by feeding back in the copy of the data in the maps
	// and forcing the pruning.
	snapshot.restore(maps)
	rec.Prune()

	lastDump = nil
	if !assert.Eventually(
		t,
		func() bool {
			lastDump = dump(maps, frontendAddrs[0], true)
			ok := len(lastDump) == 0
			if !ok {
				// Keep re-pruning as a fault may have been injected.
				rec.Prune()
			}
			return ok
		},
		5*time.Second,
		50*time.Millisecond) {
		t.Fatalf("Expected BPF maps to be empty after pruning, instead they contain: %v", lastDump)
	}
}

// sanitizeTables clears non-deterministic data in the table output such as timestamps.
func sanitizeTables(dump []byte) []byte {
	r := regexp.MustCompile(`\([^\)]* ago\)`)
	return r.ReplaceAll(dump, []byte("(??? ago)"))
}

func checkTablesAndMaps(db *statedb.DB, writer *Writer, maps lbmaps, testDataPath string) bool {
	allDone := true
	count := 0
	for fe := range writer.Frontends().All(db.ReadTxn()) {
		if fe.Status.Kind != reconciler.StatusKindDone {
			allDone = false
		}
		count++
	}
	if count == 0 || !allDone {
		return false
	}

	var tableBuf bytes.Buffer
	writer.DebugDump(db.ReadTxn(), &tableBuf)
	actualTables := tableBuf.Bytes()

	var expectedTables []byte
	if expectedData, err := os.ReadFile(path.Join(testDataPath, "expected.tables")); err == nil {
		expectedTables = expectedData
	}
	actualTables = sanitizeTables(actualTables)
	expectedTables = sanitizeTables(expectedTables)

	os.WriteFile(path.Join(testDataPath, "actual.tables"), actualTables, 0644)

	var expectedMaps []mapDump
	if expectedData, err := os.ReadFile(path.Join(testDataPath, "expected.maps")); err == nil {
		expectedMaps = strings.Split(strings.TrimSpace(string(expectedData)), "\n")
	}
	actualMaps := dump(maps, frontendAddrs[0], true)

	actualPath := path.Join(testDataPath, "actual.maps")
	os.WriteFile(
		actualPath,
		[]byte(strings.Join(actualMaps, "\n")+"\n"),
		0644,
	)
	return bytes.Equal(actualTables, expectedTables) && slices.Equal(expectedMaps, actualMaps)
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

func hasYamlFiles(path string) bool {
	dirs, err := os.ReadDir(path)
	if err != nil {
		return false
	}

	for _, ent := range dirs {
		if strings.HasSuffix(ent.Name(), ".yaml") {
			return true
		}
	}
	return false
}

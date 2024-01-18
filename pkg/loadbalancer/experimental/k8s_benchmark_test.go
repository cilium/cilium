package experimental

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"runtime"
	"runtime/pprof"
	"slices"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	golang_maps "golang.org/x/exp/maps"
)

func BenchmarkServiceAndEndpoint(b *testing.B) {
	// As we're using k8s.Endpoints we need to set this to ask ParseEndpoint*
	// to handle the termination state. Eventually this should migrate to the
	// package for the k8s data source.
	oldEnableK8sTerminatingEndpoint := option.Config.EnableK8sTerminatingEndpoint
	defer func() {
		option.Config.EnableK8sTerminatingEndpoint = oldEnableK8sTerminatingEndpoint
	}()
	option.Config.EnableK8sTerminatingEndpoint = true

	const testSize = 50000
	const benchmarkPath = "testdata/k8s_benchmark"

	svcs, epSlices := inputsAndOutputs(b, benchmarkPath, testSize)

	log := hivetest.Logger(b, hivetest.LogLevel(slog.LevelError))

	var maps lbmaps
	if testutils.IsPrivileged() {
		maps = &realLBMaps{
			pinned: false,
			cfg: LBMapsConfig{
				MaxSockRevNatMapEntries:  3 * testSize,
				ServiceMapMaxEntries:     3 * testSize,
				BackendMapMaxEntries:     3 * testSize,
				RevNatMapMaxEntries:      3 * testSize,
				AffinityMapMaxEntries:    3 * testSize,
				SourceRangeMapMaxEntries: 3 * testSize,
				MaglevMapMaxEntries:      3 * testSize,
			},
		}
	} else {
		maps = newFakeLBMaps()
	}

	services := make(chan resource.Event[*slim_corev1.Service], 1000)
	services <- resource.Event[*slim_corev1.Service]{
		Kind: resource.Sync,
		Done: func(error) {},
	}
	pods := make(chan resource.Event[*slim_corev1.Pod], 1)
	pods <- resource.Event[*slim_corev1.Pod]{
		Kind: resource.Sync,
		Done: func(error) {},
	}

	endpoints := make(chan resource.Event[*k8s.Endpoints], 1000)
	endpoints <- resource.Event[*k8s.Endpoints]{
		Kind: resource.Sync,
		Done: func(error) {},
	}

	var (
		writer *Writer
		db     *statedb.DB
		bo     *bpfOps
	)
	h := createHive(maps, services, pods, endpoints, &writer, &db, &bo)

	require.NoError(b, h.Start(log, context.TODO()))
	b.Cleanup(func() {
		assert.NoError(b, h.Stop(log, context.TODO()))
	})

	// We ignore b.N and do this only once since we don't clean up
	// and can't repeat this. It's fine since the test is long enough
	// that the results are useful.

	//
	// Feed in all the test objects
	//

	f, err := os.Create("cpu.prof")
	if err != nil {
		b.Fatal("could not create CPU profile: ", err)
	}

	if err := pprof.StartCPUProfile(f); err != nil {
		b.Fatal("could not start CPU profile: ", err)
	}

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	b.StartTimer()

	go func() {
		for _, svc := range svcs {
			services <- upsertEvent(svc)
		}
	}()

	go func() {
		for _, slice := range epSlices {
			endpoints <- upsertEvent(slice)
		}
	}()

	// Wait until the frontends have been marked done.
	numDone := 0
	rev := statedb.Revision(0)
	for {
		time.Sleep(5 * time.Millisecond)
		iter := writer.Frontends().LowerBound(db.ReadTxn(), statedb.ByRevision[*Frontend](rev+1))
		for fe, r, ok := iter.Next(); ok; fe, r, ok = iter.Next() {
			rev = r
			if fe.Status.Kind == reconciler.StatusKindDone {
				numDone++
			}
		}
		if numDone == len(svcs) {
			break
		}
	}

	b.StopTimer()

	pprof.StopCPUProfile()
	f.Close()

	b.ReportMetric(float64(testSize*2)/b.Elapsed().Seconds(), "objects/sec")

	// Validate that the services and backends were indeed reconciled
	// to the maps.
	backendCount := 0
	maps.DumpBackend(func(bk lbmap.BackendKey, bv lbmap.BackendValue) {
		backendCount++
	})
	require.Equal(b, testSize, backendCount, "backend count mismatch")

	serviceCount := 0
	maps.DumpService(
		func(sk lbmap.ServiceKey, sv lbmap.ServiceValue) {
			serviceCount++
		})
	// *2 entries, master slot + backend slot.
	require.Equal(b, testSize*2, serviceCount, "service count mismatch")

	// Dump how much memory we're holding after all the insertions.
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("MemStats:\n  HeapAlloc: %dKB\n  HeapObjects: %d\n  HeapSys: %dKB\n", (m.HeapAlloc-m0.HeapAlloc)/1024, m.HeapObjects-m0.HeapObjects, (m.HeapSys-m0.HeapSys)/1024)
}

func createHive(maps lbmaps,
	services chan resource.Event[*slim_corev1.Service],
	pods chan resource.Event[*slim_corev1.Pod],
	endpoints chan resource.Event[*k8s.Endpoints],
	writer **Writer,
	db **statedb.DB,
	bo **bpfOps,
) *hive.Hive {
	extConfig := ExternalConfig{
		ExternalClusterIP:     false,
		EnableSessionAffinity: true,
		NodePortMin:           option.NodePortMinDefault,
		NodePortMax:           option.NodePortMaxDefault,
	}

	return hive.New(
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
				func() ExternalConfig { return extConfig },
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
					return maps
				},
			),

			cell.Invoke(func(db_ *statedb.DB, w *Writer, bo_ *bpfOps) {
				*db = db_
				*writer = w
				*bo = bo_
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
			}),
		),
	)
}

func inputsAndOutputs(b *testing.B, benchmarkPath string, testSize int) (svcs []*slim_corev1.Service, epSlices []*k8s.Endpoints) {
	var maxServiceIPPortLength, maxBackendIPPortLength, maxNodeNameLength, maxPortNameLength, maxServiceNameLength int

	extraDigits := extraIPDigits(testSize)

	for _, svc := range readObjects[*slim_corev1.Service](b, benchmarkPath, "service") {
		currentNamespacesNameLength := len(svc.Namespace) + len("/") + len(svc.Name) + len("-000000")
		maxServiceNameLength = max(maxServiceNameLength, currentNamespacesNameLength)

		currentPortNameLength := len(svc.Spec.Ports[0].Name)
		maxPortNameLength = max(maxPortNameLength, currentPortNameLength)

		currentServiceIPPortLength := len(svc.Spec.ClusterIP) + extraDigits + len(":") + digits(float64(svc.Spec.Ports[0].Port))
		maxServiceIPPortLength = max(maxServiceIPPortLength, currentServiceIPPortLength)
	}

	for _, slice := range readObjects[*slim_discovery_v1.EndpointSlice](b, benchmarkPath, "endpointslice") {
		currentBackendIPPortLength := len(slice.Endpoints[0].Addresses[0]) + extraDigits + +len(":") + digits(float64(*slice.Ports[0].Port))
		maxBackendIPPortLength = max(maxBackendIPPortLength, currentBackendIPPortLength)

		currentNodeNameLength := len(*slice.Endpoints[0].NodeName)
		maxNodeNameLength = max(maxNodeNameLength, currentNodeNameLength)
	}

	svcs = make([]*slim_corev1.Service, 0, testSize)
	epSlices = make([]*k8s.Endpoints, 0, testSize)

	for _, svc := range readObjects[*slim_corev1.Service](b, benchmarkPath, "service") {
		for _, slice := range readObjects[*slim_discovery_v1.EndpointSlice](b, benchmarkPath, "endpointslice") {
			// We assume there is exactly one slice per service.
			if slice.Namespace != svc.Namespace || slice.Labels["kubernetes.io/service-name"] != svc.Name {
				continue
			}
			svcAddr, err := netip.ParseAddr(svc.Spec.ClusterIP)
			require.NoError(b, err)
			svcAddrAs4 := svcAddr.As4()

			sliceAddr, err := netip.ParseAddr(slice.Endpoints[0].Addresses[0])
			require.NoError(b, err)
			sliceAddrAs4 := sliceAddr.As4()

			for j := range testSize {
				// Service part
				tmpSvc := *svc
				tmpSvcAddr := svcAddrAs4
				tmpSvcAddr[2] += byte(j / 256)
				tmpSvcAddr[3] += byte(j % 256)
				tmpSvcIPString := netip.AddrFrom4(tmpSvcAddr).String()
				tmpSvc.Spec.ClusterIP = tmpSvcIPString
				tmpSvc.Spec.ClusterIPs = []string{tmpSvcIPString}

				tmpSvc.Name = fmt.Sprintf("%s-%06d", svc.Name, j)

				tmpSvc.Spec.Selector = golang_maps.Clone(svc.Spec.Selector)
				tmpSvc.Spec.Selector["name"] = fmt.Sprintf("%s-%06d", svc.Spec.Selector["name"], j)

				svcs = append(svcs, &tmpSvc)

				// Slice part
				tmpSlice := *slice
				tmpSlice.Endpoints = slices.Clone(tmpSlice.Endpoints)
				tmpSlice.Endpoints[0].Addresses = slices.Clone(tmpSlice.Endpoints[0].Addresses)
				tmpSliceAddr := sliceAddrAs4
				tmpSliceAddr[2] += byte(j / 256)
				tmpSliceAddr[3] += byte(j % 256)
				tmpSliceIPString := netip.AddrFrom4(tmpSliceAddr).String()
				tmpSlice.Endpoints[0].Addresses[0] = tmpSliceIPString

				tmpSlice.Labels = golang_maps.Clone(tmpSlice.Labels)
				tmpSlice.Labels["kubernetes.io/service-name"] = fmt.Sprintf("%s-%06d", slice.Labels["kubernetes.io/service-name"], j)

				tmpSlice.Name = fmt.Sprintf("%s-%06d", slice.Name, j)

				epSlices = append(epSlices, k8s.ParseEndpointSliceV1(&tmpSlice))
			}
		}
	}

	return
}

func digits(n float64) int {
	if n < 0 {
		panic("negative value")
	}
	if n == 0 {
		return 1
	}
	return int(math.Floor(math.Log10(n)) + 1)
}

func extraIPDigits(n int) int {
	if n > 256*256*256 {
		return 2 + 2 + 2 + digits(math.Ceil(float64(n)/(256*256*256))) - 1
	}
	if n > 256*256 {
		return 2 + 2 + digits(math.Ceil(float64(n)/(256*256))) - 1
	}
	if n > 256 {
		return 2 + digits(math.Ceil(float64(n)/256)) - 1
	}
	return digits(float64(n)) - 1
}

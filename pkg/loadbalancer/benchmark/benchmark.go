// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"math"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/cilium/stream"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	k8sTestUtils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var (
	//go:embed testdata/service.yaml
	serviceYaml []byte

	//go:embed testdata/endpointslice.yaml
	endpointSliceYaml []byte

	maglevConfig, _ = maglev.UserConfig{
		TableSize: 1021,
		HashSeed:  maglev.DefaultHashSeed,
	}.ToConfig()
)

func RunBenchmark(testSize int, iterations int, loglevel slog.Level, validate bool) {
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true

	svcs, epSlices := ServicesAndSlices(testSize)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: loglevel}))

	var maps lbmaps.LBMaps
	if testutils.IsPrivileged() {
		bpfMaps := &lbmaps.BPFLBMaps{
			Log:    log,
			Pinned: false,
			Cfg: loadbalancer.Config{
				UserConfig: loadbalancer.UserConfig{
					EnableExperimentalLB:    true,
					RetryBackoffMin:         time.Second,
					RetryBackoffMax:         time.Second,
					LBMapEntries:            3 * testSize,
					LBServiceMapEntries:     3 * testSize,
					LBBackendMapEntries:     3 * testSize,
					LBRevNatEntries:         3 * testSize,
					LBAffinityMapEntries:    3 * testSize,
					LBSourceRangeAllTypes:   false,
					LBSourceRangeMapEntries: 3 * testSize,
					LBMaglevMapEntries:      3 * testSize,
					LBSockRevNatEntries:     3 * testSize,
				},
				NodePortMin: loadbalancer.NodePortMinDefault,
				NodePortMax: loadbalancer.NodePortMaxDefault,
			},
			ExtCfg: loadbalancer.ExternalConfig{
				ZoneMapper:           &option.DaemonConfig{},
				EnableIPv4:           true,
				EnableIPv6:           true,
				KubeProxyReplacement: true,
			},
			MaglevCfg: maglevConfig,
		}
		bpfMaps.Start(context.TODO())
		maps = bpfMaps
	} else {
		maps = lbmaps.NewFakeLBMaps()
	}

	services := make(chan resource.Event[*slim_corev1.Service], 1000)
	services <- resource.Event[*slim_corev1.Service]{
		Kind: resource.Sync,
		Done: func(error) {},
	}
	endpoints := make(chan resource.Event[*k8s.Endpoints], 1000)
	endpoints <- resource.Event[*k8s.Endpoints]{
		Kind: resource.Sync,
		Done: func(error) {},
	}

	var (
		writer *writer.Writer
		db     *statedb.DB
		bo     *lbreconciler.BPFOps
	)
	h := testHive(maps, services, endpoints, &writer, &db, &bo)

	if err := h.Start(log, context.TODO()); err != nil {
		panic(err)
	}
	defer func() {
		if err := h.Stop(log, context.TODO()); err != nil {
			panic(err)
		}
	}()

	var runs []run

	for i := range iterations {
		runtime.GC()
		var memory memoryPair
		runtime.ReadMemStats(&memory.before)

		start := time.Now()

		//
		// Feed in all the test objects
		//
		fmt.Printf("Iteration %d: upsert ", i)
		for _, slice := range epSlices {
			endpoints <- upsertEvent(slice)
		}
		for _, svc := range svcs {
			services <- upsertEvent(svc)
		}

		fmt.Print("wait ")
		nextRevision := statedb.Revision(0)
		reconciled := false
		for waitStart := time.Now(); time.Now().Sub(waitStart) < 10*time.Second; time.Sleep(10 * time.Millisecond) {
			reconciled, nextRevision = fastCheckTables(db, writer, testSize, nextRevision)
			if reconciled {
				break
			}
		}
		if !reconciled {
			panic("Timeout waiting for reconciliation.")
		}

		if validate {
			if err := checkTables(db, writer, svcs, epSlices); err != nil {
				fmt.Printf("checking tables failed with error: %v", err)
				panic("")
			} else {
				fmt.Printf("table check succeeded ")
			}
		}

		insertDuration := time.Since(start)

		runtime.GC()
		runtime.ReadMemStats(&memory.after)

		startDelete := time.Now()

		fmt.Print("delete ")
		//
		// Feed in deletions of all objects.
		//
		for _, svc := range svcs {
			services <- deleteEvent(svc)
		}

		for _, slice := range epSlices {
			endpoints <- deleteEvent(slice)
		}

		fmt.Printf("wait ")
		// Tables and maps should now be empty.
		cleanedUp := false
		for waitStart := time.Now(); time.Now().Sub(waitStart) < 10*time.Second; time.Sleep(10 * time.Millisecond) {
			cleanedUp = fastCheckEmptyTablesAndState(db, writer, bo)
			cleanedUp = cleanedUp && bo.LBMaps.IsEmpty()
			if cleanedUp {
				break
			}
		}
		if !cleanedUp {
			dump := lbmaps.DumpLBMaps(bo.LBMaps, false, nil)
			panic(fmt.Sprintf("Expected BPF maps to be empty, instead they contain %d entries:\n%s", len(dump), strings.Join(dump, "\n")))
		}
		fmt.Println("ok.")

		runs = append(
			runs,
			run{
				insertDuration: insertDuration,
				deleteDuration: time.Since(startDelete),
				memstats:       &memory,
			},
		)
	}

	fmt.Println()
	fmt.Printf("Memory statistics from N=%d iterations:\n", iterations)
	printMemoryStats(mapFunc(runs, run.mem), testSize)
	fmt.Println()

	fmt.Printf("Insert statistics from N=%d iterations:\n", iterations)
	printTimeStats(mapFunc(runs, run.insert), testSize)

	fmt.Println()
	fmt.Printf("Delete statistics from N=%d iterations:\n", iterations)
	printTimeStats(mapFunc(runs, run.delete), testSize)
}

type memoryPair struct {
	before runtime.MemStats
	after  runtime.MemStats
}

type run struct {
	insertDuration time.Duration
	deleteDuration time.Duration
	memstats       *memoryPair
}

func (r run) insert() time.Duration { return r.insertDuration }
func (r run) delete() time.Duration { return r.deleteDuration }
func (r run) mem() *memoryPair      { return r.memstats }

func printMemoryStats(pairs []*memoryPair, testSize int) {
	Min, Max, Avg := calculateStatistics(pairs)
	fmt.Printf("Min: Allocated %6dkB in total, %7d objects / %6dkB still reachable (per service: %3d objs, %5dB alloc, %5dB in-use)\n", Min.alloc/1024, Min.objects, Min.inUse/1024, Min.objects/int64(testSize), Min.alloc/int64(testSize), Min.inUse/int64(testSize))
	fmt.Printf("Avg: Allocated %6dkB in total, %7d objects / %6dkB still reachable (per service: %3d objs, %5dB alloc, %5dB in-use)\n", Avg.alloc/1024, Avg.objects, Avg.inUse/1024, Avg.objects/int64(testSize), Avg.alloc/int64(testSize), Avg.inUse/int64(testSize))
	fmt.Printf("Max: Allocated %6dkB in total, %7d objects / %6dkB still reachable (per service: %3d objs, %5dB alloc, %5dB in-use)\n", Max.alloc/1024, Max.objects, Max.inUse/1024, Max.objects/int64(testSize), Max.alloc/int64(testSize), Max.inUse/int64(testSize))
}

type stats struct {
	objects, alloc, inUse int64
}

func calculateStatistics(pairs []*memoryPair) (Min, Max, Avg stats) {
	Min.objects = math.MaxInt64
	Min.alloc = math.MaxInt64
	Min.inUse = math.MaxInt64
	for _, memory := range pairs {
		var objects, alloc, inUse int64
		objects = int64(memory.after.HeapObjects - memory.before.HeapObjects)
		Min.objects = min(Min.objects, objects)
		Max.objects = max(Max.objects, objects)
		Avg.objects += objects

		alloc = int64(memory.after.TotalAlloc - memory.before.TotalAlloc)
		Min.alloc = min(Min.alloc, alloc)
		Max.alloc = max(Max.alloc, alloc)
		Avg.alloc += alloc

		inUse = int64(memory.after.HeapAlloc - memory.before.HeapAlloc)
		Min.inUse = min(Min.inUse, inUse)
		Max.inUse = max(Max.inUse, inUse)
		Avg.inUse += inUse
	}
	Avg.objects /= int64(len(pairs))
	Avg.alloc /= int64(len(pairs))
	Avg.inUse /= int64(len(pairs))
	return
}

func printTimeStats(durations []time.Duration, testSize int) {
	Min, Max, Avg := calculateTimeStats(durations)
	avgPerService := time.Duration(Avg.Nanoseconds() / int64(testSize))
	maxPerService := time.Duration(Max.Nanoseconds() / int64(testSize))
	minPerService := time.Duration(Min.Nanoseconds() / int64(testSize))

	fmt.Printf("Min: Reconciled %d objects in %-11s (%-9s per service / %6.0f services per second)\n", testSize, Min, minPerService, float64(time.Second)/float64(minPerService))
	fmt.Printf("Avg: Reconciled %d objects in %-11s (%-9s per service / %6.0f services per second)\n", testSize, Avg, avgPerService, float64(time.Second)/float64(avgPerService))
	fmt.Printf("Max: Reconciled %d objects in %-11s (%-9s per service / %6.0f services per second)\n", testSize, Max, maxPerService, float64(time.Second)/float64(maxPerService))
}

func calculateTimeStats(durations []time.Duration) (Min, Max, Avg time.Duration) {
	var Sum time.Duration
	Min = 2 * time.Hour
	for _, duration := range durations {
		Min = min(Min, duration)
		Max = max(Max, duration)
		Sum += duration
	}
	Avg = time.Duration(Sum.Nanoseconds() / int64(len(durations)) * int64(time.Nanosecond))
	return

}

func mapFunc[A, B any](xs []A, fn func(A) B) []B {
	out := make([]B, len(xs))
	for i := range xs {
		out[i] = fn(xs[i])
	}
	return out
}

func ServicesAndSlices(testSize int) (svcs []*slim_corev1.Service, epSlices []*k8s.Endpoints) {
	svcs = make([]*slim_corev1.Service, 0, testSize)
	epSlices = make([]*k8s.Endpoints, 0, testSize)

	obj, err := k8sTestUtils.DecodeObject(serviceYaml)
	if err != nil {
		panic(err)
	}
	svc := obj.(*slim_corev1.Service)

	svcAddr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		panic(err)
	}
	svcAddrAs4 := svcAddr.As4()
	for j := range testSize {
		tmpSvc := *svc
		tmpSvcAddr := svcAddrAs4
		tmpSvcAddr[2] += byte(j / 256)
		tmpSvcAddr[3] += byte(j % 256)
		tmpSvcIPString := netip.AddrFrom4(tmpSvcAddr).String()
		tmpSvc.Spec.ClusterIP = tmpSvcIPString
		tmpSvc.Spec.ClusterIPs = []string{tmpSvcIPString}

		tmpSvc.Name = fmt.Sprintf("%s-%06d", svc.Name, j)

		tmpSvc.Spec.Selector = maps.Clone(svc.Spec.Selector)
		tmpSvc.Spec.Selector["name"] = fmt.Sprintf("%s-%06d", svc.Spec.Selector["name"], j)

		svcs = append(svcs, &tmpSvc)
	}

	obj, err = k8sTestUtils.DecodeObject(endpointSliceYaml)
	if err != nil {
		panic(err)
	}
	slice := obj.(*slim_discovery_v1.EndpointSlice)

	sliceAddr, err := netip.ParseAddr(slice.Endpoints[0].Addresses[0])
	if err != nil {
		panic(err)
	}
	sliceAddrAs4 := sliceAddr.As4()
	for j := range testSize {
		tmpSlice := *slice
		tmpSlice.Endpoints = slices.Clone(tmpSlice.Endpoints)
		tmpSlice.Endpoints[0].Addresses = slices.Clone(tmpSlice.Endpoints[0].Addresses)
		tmpSliceAddr := sliceAddrAs4
		tmpSliceAddr[2] += byte(j / 256)
		tmpSliceAddr[3] += byte(j % 256)
		tmpSliceIPString := netip.AddrFrom4(tmpSliceAddr).String()
		tmpSlice.Endpoints[0].Addresses[0] = tmpSliceIPString

		tmpSlice.Labels = maps.Clone(tmpSlice.Labels)
		tmpSlice.Labels["kubernetes.io/service-name"] = fmt.Sprintf("%s-%06d", slice.Labels["kubernetes.io/service-name"], j)

		tmpSlice.Name = fmt.Sprintf("%s-%06d", slice.Name, j)

		epSlices = append(epSlices, k8s.ParseEndpointSliceV1(logging.DefaultSlogLogger, &tmpSlice))
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

func checkTables(db *statedb.DB, writer *writer.Writer, svcs []*slim_corev1.Service, epSlices []*k8s.Endpoints) error {
	txn := db.ReadTxn()
	var err error

	{
		if servicesNo := writer.Services().NumObjects(txn); servicesNo != len(svcs) {
			err = errors.Join(err, fmt.Errorf("Incorrect number of services, got %d, want %d", servicesNo, len(svcs)))
		} else {
			i := 0
			for svc := range writer.Services().All(txn) {
				want := svcs[i]
				if svc.Name.Namespace != want.Namespace {
					err = errors.Join(err, fmt.Errorf("Incorrect namespace for service #%06d, got %q, want %q", i, svc.Name.Namespace, want.Namespace))
				}
				if svc.Name.Name != want.Name {
					err = errors.Join(err, fmt.Errorf("Incorrect name for service #%06d, got %q, want %q", i, svc.Name.Name, want.Name))
				}
				if svc.Source != "k8s" {
					err = errors.Join(err, fmt.Errorf("Incorrect source for service #%06d, got %q, want %q", i, svc.Source, "k8s"))
				}
				if svc.ExtTrafficPolicy != loadbalancer.SVCTrafficPolicyCluster {
					err = errors.Join(err, fmt.Errorf("Incorrect external traffic policy for service #%06d, got %q, want %q", i, svc.ExtTrafficPolicy, loadbalancer.SVCTrafficPolicyCluster))
				}
				if svc.IntTrafficPolicy != loadbalancer.SVCTrafficPolicyCluster {
					err = errors.Join(err, fmt.Errorf("Incorrect internal traffic policy for service #%06d, got %q, want %q", i, svc.IntTrafficPolicy, loadbalancer.SVCTrafficPolicyCluster))
				}

				i++
			}
		}
	}

	{
		if frontendsNo := writer.Frontends().NumObjects(txn); frontendsNo != len(svcs) {
			err = errors.Join(err, fmt.Errorf("Incorrect number of frontends, got %d, want %d", frontendsNo, len(svcs)))
		} else {
			i := 0
			for fe := range writer.Frontends().All(txn) {
				want := svcs[i]
				if fe.ServiceName.Namespace != want.Namespace {
					err = errors.Join(err, fmt.Errorf("Incorrect namespace for frontend #%06d, got %q, want %q", i, fe.ServiceName.Namespace, want.Namespace))
				}
				if fe.ServiceName.Name != want.Name {
					err = errors.Join(err, fmt.Errorf("Incorrect name for frontend #%06d, got %q, want %q", i, fe.ServiceName.Name, want.Name))
				}
				wantIP, _ := netip.ParseAddr(want.Spec.ClusterIP)
				if fe.Address.AddrCluster.Addr() != wantIP {
					err = errors.Join(err, fmt.Errorf("Incorrect address for frontend #%06d, got %v, want %v", i, fe.Address.AddrCluster.Addr(), wantIP))
				}
				if fe.Type != loadbalancer.SVCType(want.Spec.Type) {
					err = errors.Join(err, fmt.Errorf("Incorrect service type for frontend #%06d, got %v, want %v", i, fe.Type, loadbalancer.SVCType(want.Spec.Type)))
				}
				if fe.PortName != loadbalancer.FEPortName(want.Spec.Ports[0].Name) {
					err = errors.Join(err, fmt.Errorf("Incorrect port name for frontend #%06d, got %v, want %v", i, fe.PortName, loadbalancer.FEPortName(want.Spec.Ports[0].Name)))
				}
				if fe.Status.Kind != "Done" {
					err = errors.Join(err, fmt.Errorf("Incorrect status for frontend #%06d, got %v, want %v", i, fe.Status.Kind, "Done"))
				}
				backends := slices.Collect(statedb.ToSeq(iter.Seq2[loadbalancer.BackendParams, statedb.Revision](fe.Backends)))
				for wantAddr := range epSlices[i].Backends { // There is only one element in this map.
					if backends[0].Address.AddrCluster != wantAddr {
						err = errors.Join(err, fmt.Errorf("Incorrect backend address for frontend #%06d, got %v, want %v", i, backends[0].Address.AddrCluster, wantAddr))
					}
				}

				i++
			}
		}
	}

	{
		if backendsNo := writer.Backends().NumObjects(txn); backendsNo != len(epSlices) {
			err = errors.Join(err, fmt.Errorf("Incorrect number of backends, got %d, want %d", backendsNo, len(epSlices)))
		} else {
			i := 0
			for be := range writer.Backends().All(txn) {
				want := epSlices[i]
				for wantAddr, wantBe := range want.Backends { // There is only one element in this map.
					if be.Address.AddrCluster != wantAddr {
						err = errors.Join(err, fmt.Errorf("Incorrect address for backend #%06d, got %v, want %v", i, be.Address.AddrCluster, wantAddr))
					}
					for _, wantPort := range wantBe.Ports { // There is only one element in this map.
						if be.Address.Port != wantPort.Port {
							err = errors.Join(err, fmt.Errorf("Incorrect port for backend #%06d, got %v, want %v", i, be.Address.Port, wantPort.Port))
						}
						if be.Address.Protocol != wantPort.Protocol {
							err = errors.Join(err, fmt.Errorf("Incorrect protocol for backend #%06d, got %v, want %v", i, be.Address.Protocol, wantPort.Protocol))
						}
					}
				}
				if be.Instances.Len() != 1 {
					err = errors.Join(err, fmt.Errorf("Incorrect instances count for backend #%06d, got %v, want %v", i, be.Instances.Len(), 1))
				} else {
					for k, instance := range be.Instances.All() { // There should
						if k.ServiceName.Name != svcs[i].Name {
							err = errors.Join(err, fmt.Errorf("Incorrect service name for backend #%06d, got %v, want %v", i, k.ServiceName.Name, svcs[i].Name))
						}
						if state, tmpErr := instance.State.String(); tmpErr != nil || state != "active" {
							err = errors.Join(err, fmt.Errorf("Incorrect state for backend #%06d, got %q, want %q", i, state, "active"))
						}
						if instance.PortNames[0] != svcs[i].Spec.Ports[0].Name {
							err = errors.Join(err, fmt.Errorf("Incorrect instance port name for backend #%06d, got %q, want %q", i, instance.PortNames[0], svcs[i].Spec.Ports[0].Name))
						}
					}
				}

				i++
			}
		}
	}

	return err
}

var (
	nodePortAddrs = []netip.Addr{
		netip.MustParseAddr("10.0.0.3"),
		netip.MustParseAddr("2002::1"),
	}
)

func testHive(maps lbmaps.LBMaps,
	services chan resource.Event[*slim_corev1.Service],
	endpoints chan resource.Event[*k8s.Endpoints],
	writerPtr **writer.Writer,
	db **statedb.DB,
	bo **lbreconciler.BPFOps,
) *hive.Hive {
	extConfig := loadbalancer.ExternalConfig{
		ZoneMapper: &option.DaemonConfig{},
		EnableIPv4: true,
		EnableIPv6: true,
	}

	return hive.New(
		cell.Module(
			"loadbalancer-test",
			"Test module",

			client.FakeClientCell,
			node.LocalNodeStoreCell,

			cell.Provide(
				func() loadbalancer.Config {
					return loadbalancer.Config{
						UserConfig:  loadbalancer.DefaultUserConfig,
						NodePortMin: loadbalancer.NodePortMinDefault,
						NodePortMax: loadbalancer.NodePortMaxDefault,
					}
				},
				func() loadbalancer.ExternalConfig { return extConfig },

				func() reflectors.StreamsOut {
					return reflectors.StreamsOut{
						ServicesStream:  stream.FromChannel(services),
						EndpointsStream: stream.FromChannel(endpoints),
					}
				},

				func(lc cell.Lifecycle) lbmaps.LBMaps {
					if rm, ok := maps.(*lbmaps.BPFLBMaps); ok {
						lc.Append(rm)
					}
					return maps
				},

				func(lc cell.Lifecycle) (*maglev.Maglev, maglev.Config) {
					m := maglev.New(maglevConfig, lc)
					return m, maglevConfig
				},
			),

			daemonk8s.PodTableCell,

			cell.Invoke(func(db_ *statedb.DB, w *writer.Writer, bo_ *lbreconciler.BPFOps) {
				*db = db_
				*writerPtr = w
				*bo = bo_
			}),

			// Provides [Writer] API and the load-balancing tables.
			writer.Cell,

			// Reflects Kubernetes services and endpoints to the load-balancing tables
			// using the [Writer].
			cell.Invoke(reflectors.RegisterK8sReflector),

			// Reconcile tables to BPF maps
			lbreconciler.Cell,

			cell.Provide(lbmaps.NetnsCookieSupportFunc),

			cell.Provide(
				tables.NewNodeAddressTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
				source.NewSources,
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
}

func fastCheckTables(db *statedb.DB, writer *writer.Writer, expectedFrontends int, lastPendingRevision statedb.Revision) (reconciled bool, nextRevision statedb.Revision) {
	txn := db.ReadTxn()
	if writer.Frontends().NumObjects(txn) < expectedFrontends {
		return false, 0
	}
	var rev uint64
	var fe *loadbalancer.Frontend
	for fe, rev = range writer.Frontends().LowerBound(txn, statedb.ByRevision[*loadbalancer.Frontend](lastPendingRevision)) {
		if fe.Status.Kind != reconciler.StatusKindDone {
			return false, rev
		}
	}
	return true, rev // Here, it is the last reconciled revision rather than the first non-reconciled revision.
}

func fastCheckEmptyTablesAndState(db *statedb.DB, writer *writer.Writer, bo *lbreconciler.BPFOps) bool {
	txn := db.ReadTxn()
	if writer.Frontends().NumObjects(txn) > 0 || writer.Backends().NumObjects(txn) > 0 || writer.Services().NumObjects(txn) > 0 {
		return false
	}
	return bo.StateIsEmpty()
}

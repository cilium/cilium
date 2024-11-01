// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	k8sTestUtils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var (
	//go:embed testdata/service.yaml
	serviceYaml []byte

	//go:embed testdata/endpointslice.yaml
	endpointSliceYaml []byte
)

func RunBenchmark(testSize int, iterations int, loglevel slog.Level, validate bool) {
	// As we're using k8s.Endpoints we need to set this to ask ParseEndpoint*
	// to handle the termination state. Eventually this should migrate to the
	// package for the k8s data source.
	option.Config.EnableK8sTerminatingEndpoint = true

	svcs, epSlices := ServicesAndSlices(testSize)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: loglevel}))

	var maps experimental.LBMaps
	if testutils.IsPrivileged() {
		maps = &experimental.BPFLBMaps{
			Pinned: false,
			Cfg: experimental.LBMapsConfig{
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
		maps = experimental.NewFakeLBMaps()
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
		writer *experimental.Writer
		db     *statedb.DB
		bo     *experimental.BPFOps
	)
	h := experimental.TestHive(maps, services, pods, endpoints, 0.0, &writer, &db, &bo)

	if err := h.Start(log, context.TODO()); err != nil {
		panic(err)
	}
	defer func() {
		if err := h.Stop(log, context.TODO()); err != nil {
			panic(err)
		}
	}()

	var runs []run

	for i := 0; i < iterations; i++ {
		runtime.GC()
		var memory memoryPair
		runtime.ReadMemStats(&memory.before)

		start := time.Now()

		//
		// Feed in all the test objects
		//
		fmt.Printf("Iteration %d: upsert ", i)
		for _, svc := range svcs {
			services <- experimental.UpsertEvent(svc)
		}

		for _, slice := range epSlices {
			endpoints <- experimental.UpsertEvent(slice)
		}

		fmt.Print("wait ")
		nextRevision := statedb.Revision(0)
		reconciled := false
		for waitStart := time.Now(); time.Now().Sub(waitStart) < 10*time.Second; time.Sleep(10 * time.Millisecond) {
			reconciled, nextRevision = experimental.FastCheckTables(db, writer, testSize, nextRevision)
			if reconciled {
				break
			}
		}
		if !reconciled {
			panic("Timeout waiting for reconciliation.")
		}

		if validate {
			if err := experimental.CheckTables(db, writer, svcs, epSlices); err != nil {
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
			services <- experimental.DeleteEvent(svc)
		}

		for _, slice := range epSlices {
			endpoints <- experimental.DeleteEvent(slice)
		}

		fmt.Printf("wait ")
		// Tables and maps should now be empty.
		cleanedUp := false
		for waitStart := time.Now(); time.Now().Sub(waitStart) < 10*time.Second; time.Sleep(10 * time.Millisecond) {
			cleanedUp = experimental.FastCheckEmptyTables(db, writer, bo)
			cleanedUp = cleanedUp && bo.LBMaps.IsEmpty()
			if cleanedUp {
				break
			}
		}
		if !cleanedUp {
			dump := experimental.DumpLBMaps(bo.LBMaps, loadbalancer.L3n4Addr{}, false, nil)
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

		epSlices = append(epSlices, k8s.ParseEndpointSliceV1(&tmpSlice))
	}
	return
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/statedb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

type Config struct {
	Services                         int
	EndpointsPerService              int
	Iterations                       int
	ServiceMatcherLRPs               int
	LRPBackends                      int
	UnmatchedLRPNamespacePods        int
	ServiceMatcherLRPSharedNamespace bool
	ReflectorWaitTime                time.Duration
	LogLevel                         slog.Level
	Validate                         bool
}

func RunBenchmark(cfg Config) {
	if cfg.Services < 1 {
		panic("services must be at least 1")
	}
	if cfg.EndpointsPerService < 1 {
		panic("endpoints per service must be at least 1")
	}
	if cfg.ServiceMatcherLRPs < 0 || cfg.ServiceMatcherLRPs > cfg.Services {
		panic("service matcher LRPs must be between 0 and the number of services")
	}
	if cfg.ServiceMatcherLRPs > 0 && cfg.LRPBackends < 1 {
		panic("LRP backends must be at least 1 when service matcher LRPs are enabled")
	}
	if cfg.ServiceMatcherLRPs == 0 && cfg.UnmatchedLRPNamespacePods > 0 {
		panic("unmatched LRP namespace pods require at least one ServiceMatcher LRP")
	}
	if cfg.ServiceMatcherLRPs == 0 && cfg.ServiceMatcherLRPSharedNamespace {
		panic("shared LRP namespace requires at least one ServiceMatcher LRP")
	}
	if cfg.LRPBackends < 0 {
		panic("LRP backends cannot be negative")
	}
	if cfg.UnmatchedLRPNamespacePods < 0 {
		panic("unmatched LRP namespace pods cannot be negative")
	}
	if cfg.Iterations < 1 {
		panic("iterations must be at least 1")
	}
	if cfg.ReflectorWaitTime <= 0 {
		panic("reflector wait time must be greater than 0")
	}

	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))

	objects := generateBenchmarkObjects(log, cfg)

	var maps lbmaps.LBMaps
	if testutils.IsPrivileged() {
		bpfMaps := &lbmaps.BPFLBMaps{
			Log:    log,
			Pinned: false,
			Cfg: loadbalancer.Config{
				UserConfig: loadbalancer.UserConfig{
					RetryBackoffMin:         time.Second,
					RetryBackoffMax:         time.Second,
					LBMapEntries:            3 * objects.backendCount,
					LBServiceMapEntries:     3 * cfg.Services,
					LBBackendMapEntries:     3 * objects.backendCount,
					LBRevNatEntries:         3 * cfg.Services,
					LBAffinityMapEntries:    3 * objects.backendCount,
					LBSourceRangeAllTypes:   false,
					LBSourceRangeMapEntries: 3 * cfg.Services,
					LBMaglevMapEntries:      3 * objects.backendCount,
					LBSockRevNatEntries:     3 * objects.backendCount,
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
	endpoints := make(chan resource.Event[*k8s.Endpoints], 1000)

	var (
		writer   *writer.Writer
		db       *statedb.DB
		bo       *lbreconciler.BPFOps
		client   *k8sClient.FakeClientset
		podTable statedb.Table[k8sTables.LocalPod]
		lrpTable statedb.Table[*redirectpolicy.LocalRedirectPolicy]
	)
	h := testHive(maps, services, endpoints, cfg.ServiceMatcherLRPs > 0, cfg.ReflectorWaitTime, &writer, &db, &bo, &client, &podTable, &lrpTable)

	if err := h.Start(log, context.TODO()); err != nil {
		panic(err)
	}
	defer func() {
		if err := h.Stop(log, context.TODO()); err != nil {
			panic(err)
		}
	}()

	var runs []run
	reconciliationTimeout := 10 * time.Second
	if cfg.ServiceMatcherLRPs > 0 {
		reconciliationTimeout = 5 * time.Minute
	}

	for i := range cfg.Iterations {
		var memory memoryPair

		//
		// Prepare the LRP inputs. Pod and policy creation goes through the fake
		// Kubernetes client and is excluded from the reconciliation measurement.
		//
		fmt.Printf("Iteration %d: ", i)
		if cfg.ServiceMatcherLRPs > 0 {
			fmt.Print("setup pods ")
			if err := createPods(context.TODO(), client, objects.pods); err != nil {
				panic(err)
			}
			if !waitForTableSize(db, podTable, len(objects.pods), reconciliationTimeout) {
				panic("Timeout waiting for pods.")
			}
			fmt.Print("policies ")
			if err := createLRPs(context.TODO(), client, objects.lrps); err != nil {
				panic(err)
			}
			if !waitForTableSize(db, lrpTable, len(objects.lrps), reconciliationTimeout) {
				panic("Timeout waiting for local redirect policies.")
			}
			if err := validateServiceMatcherLRPs(db, lrpTable, objects); err != nil {
				panic(fmt.Sprintf("invalid Local Redirect Policy benchmark workload: %v", err))
			}
		}

		runtime.GC()
		runtime.ReadMemStats(&memory.before)
		start := time.Now()

		fmt.Print("upsert ")
		for _, slice := range objects.endpointSlices {
			endpoints <- upsertEvent(slice)
		}
		for _, svc := range objects.services {
			services <- upsertEvent(svc)
		}

		fmt.Print("wait ")
		nextRevision := statedb.Revision(0)
		reconciled := false
		expectedRedirects := max(cfg.ServiceMatcherLRPs, 0)
		for waitStart := time.Now(); time.Since(waitStart) < reconciliationTimeout; time.Sleep(10 * time.Millisecond) {
			reconciled, nextRevision = fastCheckTables(db, writer, cfg.Services, expectedRedirects, nextRevision)
			if reconciled {
				break
			}
		}
		if !reconciled {
			panic("Timeout waiting for reconciliation.")
		}

		if cfg.Validate {
			if err := checkTables(db, writer, objects); err != nil {
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
		for _, svc := range objects.services {
			services <- deleteEvent(svc)
		}

		for _, slice := range objects.endpointSlices {
			endpoints <- deleteEvent(slice)
		}
		if cfg.ServiceMatcherLRPs > 0 {
			if err := deleteLRPs(context.TODO(), client, objects.lrps); err != nil {
				panic(err)
			}
			if err := deletePods(context.TODO(), client, objects.pods); err != nil {
				panic(err)
			}
		}

		fmt.Printf("wait ")
		// Tables and maps should now be empty.
		cleanedUp := false
		for waitStart := time.Now(); time.Since(waitStart) < reconciliationTimeout; time.Sleep(10 * time.Millisecond) {
			cleanedUp = fastCheckEmptyTablesAndState(db, writer, bo, podTable, lrpTable)
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
	fmt.Printf("Memory statistics from N=%d iterations:\n", cfg.Iterations)
	printMemoryStats(mapFunc(runs, run.mem), cfg.Services)
	fmt.Println()

	fmt.Printf("Insert statistics from N=%d iterations:\n", cfg.Iterations)
	printTimeStats(mapFunc(runs, run.insert), cfg.Services)

	fmt.Println()
	fmt.Printf("Delete statistics from N=%d iterations:\n", cfg.Iterations)
	printTimeStats(mapFunc(runs, run.delete), cfg.Services)
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

func createPods(ctx context.Context, client *k8sClient.FakeClientset, pods []*slim_corev1.Pod) error {
	for _, pod := range pods {
		if _, err := client.Slim().CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

func deletePods(ctx context.Context, client *k8sClient.FakeClientset, pods []*slim_corev1.Pod) error {
	for _, pod := range pods {
		if err := client.Slim().CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("delete pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

func createLRPs(ctx context.Context, client *k8sClient.FakeClientset, lrps []*ciliumv2.CiliumLocalRedirectPolicy) error {
	for _, lrp := range lrps {
		if _, err := client.CiliumV2().CiliumLocalRedirectPolicies(lrp.Namespace).Create(ctx, lrp, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create local redirect policy %s/%s: %w", lrp.Namespace, lrp.Name, err)
		}
	}
	return nil
}

func deleteLRPs(ctx context.Context, client *k8sClient.FakeClientset, lrps []*ciliumv2.CiliumLocalRedirectPolicy) error {
	for _, lrp := range lrps {
		if err := client.CiliumV2().CiliumLocalRedirectPolicies(lrp.Namespace).Delete(ctx, lrp.Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("delete local redirect policy %s/%s: %w", lrp.Namespace, lrp.Name, err)
		}
	}
	return nil
}

func waitForTableSize[Obj any](db *statedb.DB, table statedb.Table[Obj], expected int, timeout time.Duration) bool {
	for start := time.Now(); time.Since(start) < timeout; time.Sleep(10 * time.Millisecond) {
		if table.NumObjects(db.ReadTxn()) == expected {
			return true
		}
	}
	return false
}

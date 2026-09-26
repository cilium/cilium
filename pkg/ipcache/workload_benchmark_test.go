// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/cilium/cilium/pkg/types"
)

const workloadMetadataBenchmarkEntries = 100_000

// k8sMetadataWithoutWorkload mirrors the K8sMetadata layout before workload
// propagation was added.
type k8sMetadataWithoutWorkload struct {
	Namespace  string
	PodName    string
	PodUID     string
	NamedPorts types.NamedPortMap
}

type workloadMetadataBenchmarkInput struct {
	keys       []string
	namespaces []string
	pods       []string
	uids       []string
	workloads  []string
}

func newWorkloadMetadataBenchmarkInput(entries int) workloadMetadataBenchmarkInput {
	// Build the strings before taking heap samples so both variants retain the
	// same inputs and the measurement isolates the metadata structures.
	input := workloadMetadataBenchmarkInput{
		keys:       make([]string, entries),
		namespaces: make([]string, entries),
		pods:       make([]string, entries),
		uids:       make([]string, entries),
		workloads:  make([]string, entries),
	}
	for i := range entries {
		input.keys[i] = fmt.Sprintf("10.%d.%d.%d", (i/62500)%250, (i/250)%250, i%250+1)
		input.namespaces[i] = fmt.Sprintf("namespace-%03d", i%100)
		input.pods[i] = fmt.Sprintf("checkout-%06d-7c9f55d4b9-abcde", i)
		input.uids[i] = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		input.workloads[i] = fmt.Sprintf("checkout-%06d", i)
	}
	return input
}

var (
	metadataWithoutWorkloadSink map[string]k8sMetadataWithoutWorkload
	metadataWithWorkloadSink    map[string]K8sMetadata
)

func BenchmarkK8sMetadataHeap(b *testing.B) {
	input := newWorkloadMetadataBenchmarkInput(workloadMetadataBenchmarkEntries)

	b.Run("without-workload", func(b *testing.B) {
		var heapBytes uint64
		iterations := 0
		b.ReportAllocs()

		for b.Loop() {
			b.StopTimer()
			metadataWithoutWorkloadSink = nil
			metadataWithWorkloadSink = nil
			debug.FreeOSMemory()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			b.StartTimer()

			metadata := make(map[string]k8sMetadataWithoutWorkload, len(input.keys))
			for i := range input.keys {
				metadata[input.keys[i]] = k8sMetadataWithoutWorkload{
					Namespace: input.namespaces[i],
					PodName:   input.pods[i],
					PodUID:    input.uids[i],
				}
			}

			b.StopTimer()
			metadataWithoutWorkloadSink = metadata
			runtime.ReadMemStats(&after)
			heapBytes += after.HeapAlloc - before.HeapAlloc
			iterations++
			b.StartTimer()
		}

		b.StopTimer()
		b.ReportMetric(float64(heapBytes)/float64(iterations*len(input.keys)), "heap-B/entry")
		b.ReportMetric(float64(unsafe.Sizeof(k8sMetadataWithoutWorkload{})), "struct-B")
	})

	b.Run("with-workload", func(b *testing.B) {
		var heapBytes uint64
		iterations := 0
		b.ReportAllocs()

		for b.Loop() {
			b.StopTimer()
			metadataWithoutWorkloadSink = nil
			metadataWithWorkloadSink = nil
			debug.FreeOSMemory()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			b.StartTimer()

			metadata := make(map[string]K8sMetadata, len(input.keys))
			for i := range input.keys {
				metadata[input.keys[i]] = K8sMetadata{
					Namespace: input.namespaces[i],
					PodName:   input.pods[i],
					PodUID:    input.uids[i],
					Workload: &K8sWorkload{
						Name: input.workloads[i],
						Kind: "Deployment",
					},
				}
			}

			b.StopTimer()
			metadataWithWorkloadSink = metadata
			runtime.ReadMemStats(&after)
			heapBytes += after.HeapAlloc - before.HeapAlloc
			iterations++
			b.StartTimer()
		}

		b.StopTimer()
		b.ReportMetric(float64(heapBytes)/float64(iterations*len(input.keys)), "heap-B/entry")
		b.ReportMetric(float64(unsafe.Sizeof(K8sMetadata{})), "struct-B")
	})

	runtime.KeepAlive(input)
}

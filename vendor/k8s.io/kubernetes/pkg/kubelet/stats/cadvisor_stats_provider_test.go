/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package stats

import (
	"testing"

	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	"github.com/stretchr/testify/assert"

	statsapi "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
	cadvisortest "k8s.io/kubernetes/pkg/kubelet/cadvisor/testing"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	containertest "k8s.io/kubernetes/pkg/kubelet/container/testing"
	"k8s.io/kubernetes/pkg/kubelet/leaky"
)

func TestRemoveTerminatedContainerInfo(t *testing.T) {
	const (
		seedPastPod0Infra      = 1000
		seedPastPod0Container0 = 2000
		seedPod0Infra          = 3000
		seedPod0Container0     = 4000
	)
	const (
		namespace = "test"
		pName0    = "pod0"
		cName00   = "c0"
	)
	infos := map[string]cadvisorapiv2.ContainerInfo{
		// ContainerInfo with past creation time and no CPU/memory usage for
		// simulating uncleaned cgroups of already terminated containers, which
		// should not be shown in the results.
		"/pod0-i-terminated-1":  getTerminatedContainerInfo(seedPastPod0Infra, pName0, namespace, leaky.PodInfraContainerName),
		"/pod0-c0-terminated-1": getTerminatedContainerInfo(seedPastPod0Container0, pName0, namespace, cName00),

		// Same as above but uses the same creation time as the latest
		// containers. They are terminated containers, so they should not be in
		// the results.
		"/pod0-i-terminated-2":  getTerminatedContainerInfo(seedPod0Infra, pName0, namespace, leaky.PodInfraContainerName),
		"/pod0-c0-terminated-2": getTerminatedContainerInfo(seedPod0Container0, pName0, namespace, cName00),

		// The latest containers, which should be in the results.
		"/pod0-i":  getTestContainerInfo(seedPod0Infra, pName0, namespace, leaky.PodInfraContainerName),
		"/pod0-c0": getTestContainerInfo(seedPod0Container0, pName0, namespace, cName00),

		// Duplicated containers with non-zero CPU and memory usage. This case
		// shouldn't happen unless something goes wrong, but we want to test
		// that the metrics reporting logic works in this scenario.
		"/pod0-i-duplicated":  getTestContainerInfo(seedPod0Infra, pName0, namespace, leaky.PodInfraContainerName),
		"/pod0-c0-duplicated": getTestContainerInfo(seedPod0Container0, pName0, namespace, cName00),
	}
	output := removeTerminatedContainerInfo(infos)
	assert.Len(t, output, 4)
	for _, c := range []string{"/pod0-i", "/pod0-c0", "/pod0-i-duplicated", "/pod0-c0-duplicated"} {
		if _, found := output[c]; !found {
			t.Errorf("%q is expected to be in the output\n", c)
		}
	}
}

func TestCadvisorListPodStats(t *testing.T) {
	const (
		namespace0 = "test0"
		namespace2 = "test2"
	)
	const (
		seedRoot           = 0
		seedRuntime        = 100
		seedKubelet        = 200
		seedMisc           = 300
		seedPod0Infra      = 1000
		seedPod0Container0 = 2000
		seedPod0Container1 = 2001
		seedPod1Infra      = 3000
		seedPod1Container  = 4000
		seedPod2Infra      = 5000
		seedPod2Container  = 6000
	)
	const (
		pName0 = "pod0"
		pName1 = "pod1"
		pName2 = "pod0" // ensure pName2 conflicts with pName0, but is in a different namespace
	)
	const (
		cName00 = "c0"
		cName01 = "c1"
		cName10 = "c0" // ensure cName10 conflicts with cName02, but is in a different pod
		cName20 = "c1" // ensure cName20 conflicts with cName01, but is in a different pod + namespace
	)
	const (
		rootfsCapacity    = uint64(10000000)
		rootfsAvailable   = uint64(5000000)
		rootfsInodesFree  = uint64(1000)
		rootfsInodes      = uint64(2000)
		imagefsCapacity   = uint64(20000000)
		imagefsAvailable  = uint64(8000000)
		imagefsInodesFree = uint64(2000)
		imagefsInodes     = uint64(4000)
	)

	prf0 := statsapi.PodReference{Name: pName0, Namespace: namespace0, UID: "UID" + pName0}
	prf1 := statsapi.PodReference{Name: pName1, Namespace: namespace0, UID: "UID" + pName1}
	prf2 := statsapi.PodReference{Name: pName2, Namespace: namespace2, UID: "UID" + pName2}
	infos := map[string]cadvisorapiv2.ContainerInfo{
		"/":              getTestContainerInfo(seedRoot, "", "", ""),
		"/docker-daemon": getTestContainerInfo(seedRuntime, "", "", ""),
		"/kubelet":       getTestContainerInfo(seedKubelet, "", "", ""),
		"/system":        getTestContainerInfo(seedMisc, "", "", ""),
		// Pod0 - Namespace0
		"/pod0-i":  getTestContainerInfo(seedPod0Infra, pName0, namespace0, leaky.PodInfraContainerName),
		"/pod0-c0": getTestContainerInfo(seedPod0Container0, pName0, namespace0, cName00),
		"/pod0-c1": getTestContainerInfo(seedPod0Container1, pName0, namespace0, cName01),
		// Pod1 - Namespace0
		"/pod1-i":  getTestContainerInfo(seedPod1Infra, pName1, namespace0, leaky.PodInfraContainerName),
		"/pod1-c0": getTestContainerInfo(seedPod1Container, pName1, namespace0, cName10),
		// Pod2 - Namespace2
		"/pod2-i":  getTestContainerInfo(seedPod2Infra, pName2, namespace2, leaky.PodInfraContainerName),
		"/pod2-c0": getTestContainerInfo(seedPod2Container, pName2, namespace2, cName20),
	}

	freeRootfsInodes := rootfsInodesFree
	totalRootfsInodes := rootfsInodes
	rootfs := cadvisorapiv2.FsInfo{
		Capacity:   rootfsCapacity,
		Available:  rootfsAvailable,
		InodesFree: &freeRootfsInodes,
		Inodes:     &totalRootfsInodes,
	}

	freeImagefsInodes := imagefsInodesFree
	totalImagefsInodes := imagefsInodes
	imagefs := cadvisorapiv2.FsInfo{
		Capacity:   imagefsCapacity,
		Available:  imagefsAvailable,
		InodesFree: &freeImagefsInodes,
		Inodes:     &totalImagefsInodes,
	}

	// memory limit overrides for each container (used to test available bytes if a memory limit is known)
	memoryLimitOverrides := map[string]uint64{
		"/":        uint64(1 << 30),
		"/pod2-c0": uint64(1 << 15),
	}
	for name, memoryLimitOverride := range memoryLimitOverrides {
		info, found := infos[name]
		if !found {
			t.Errorf("No container defined with name %v", name)
		}
		info.Spec.Memory.Limit = memoryLimitOverride
		infos[name] = info
	}

	options := cadvisorapiv2.RequestOptions{
		IdType:    cadvisorapiv2.TypeName,
		Count:     2,
		Recursive: true,
	}

	mockCadvisor := new(cadvisortest.Mock)
	mockCadvisor.
		On("ContainerInfoV2", "/", options).Return(infos, nil).
		On("RootFsInfo").Return(rootfs, nil).
		On("ImagesFsInfo").Return(imagefs, nil)

	mockRuntime := new(containertest.Mock)
	mockRuntime.
		On("ImageStats").Return(&kubecontainer.ImageStats{TotalStorageBytes: 123}, nil)

	resourceAnalyzer := &fakeResourceAnalyzer{}

	p := NewCadvisorStatsProvider(mockCadvisor, resourceAnalyzer, nil, nil, mockRuntime)
	pods, err := p.ListPodStats()
	assert.NoError(t, err)

	assert.Equal(t, 3, len(pods))
	indexPods := make(map[statsapi.PodReference]statsapi.PodStats, len(pods))
	for _, pod := range pods {
		indexPods[pod.PodRef] = pod
	}

	// Validate Pod0 Results
	ps, found := indexPods[prf0]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 2)
	indexCon := make(map[string]statsapi.ContainerStats, len(ps.Containers))
	for _, con := range ps.Containers {
		indexCon[con.Name] = con
	}
	con := indexCon[cName00]
	assert.EqualValues(t, testTime(creationTime, seedPod0Container0).Unix(), con.StartTime.Time.Unix())
	checkCPUStats(t, "Pod0Container0", seedPod0Container0, con.CPU)
	checkMemoryStats(t, "Pod0Conainer0", seedPod0Container0, infos["/pod0-c0"], con.Memory)

	con = indexCon[cName01]
	assert.EqualValues(t, testTime(creationTime, seedPod0Container1).Unix(), con.StartTime.Time.Unix())
	checkCPUStats(t, "Pod0Container1", seedPod0Container1, con.CPU)
	checkMemoryStats(t, "Pod0Container1", seedPod0Container1, infos["/pod0-c1"], con.Memory)

	assert.EqualValues(t, testTime(creationTime, seedPod0Infra).Unix(), ps.StartTime.Time.Unix())
	checkNetworkStats(t, "Pod0", seedPod0Infra, ps.Network)

	// Validate Pod1 Results
	ps, found = indexPods[prf1]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 1)
	con = ps.Containers[0]
	assert.Equal(t, cName10, con.Name)
	checkCPUStats(t, "Pod1Container0", seedPod1Container, con.CPU)
	checkMemoryStats(t, "Pod1Container0", seedPod1Container, infos["/pod1-c0"], con.Memory)
	checkNetworkStats(t, "Pod1", seedPod1Infra, ps.Network)

	// Validate Pod2 Results
	ps, found = indexPods[prf2]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 1)
	con = ps.Containers[0]
	assert.Equal(t, cName20, con.Name)
	checkCPUStats(t, "Pod2Container0", seedPod2Container, con.CPU)
	checkMemoryStats(t, "Pod2Container0", seedPod2Container, infos["/pod2-c0"], con.Memory)
	checkNetworkStats(t, "Pod2", seedPod2Infra, ps.Network)
}

func TestCadvisorImagesFsStats(t *testing.T) {
	var (
		assert       = assert.New(t)
		mockCadvisor = new(cadvisortest.Mock)
		mockRuntime  = new(containertest.Mock)

		seed        = 1000
		imageFsInfo = getTestFsInfo(seed)
		imageStats  = &kubecontainer.ImageStats{TotalStorageBytes: 100}
	)

	mockCadvisor.On("ImagesFsInfo").Return(imageFsInfo, nil)
	mockRuntime.On("ImageStats").Return(imageStats, nil)

	provider := newCadvisorStatsProvider(mockCadvisor, &fakeResourceAnalyzer{}, mockRuntime)
	stats, err := provider.ImageFsStats()
	assert.NoError(err)

	assert.Equal(imageFsInfo.Timestamp, stats.Time.Time)
	assert.Equal(imageFsInfo.Available, *stats.AvailableBytes)
	assert.Equal(imageFsInfo.Capacity, *stats.CapacityBytes)
	assert.Equal(imageStats.TotalStorageBytes, *stats.UsedBytes)
	assert.Equal(imageFsInfo.InodesFree, stats.InodesFree)
	assert.Equal(imageFsInfo.Inodes, stats.Inodes)
	assert.Equal(*imageFsInfo.Inodes-*imageFsInfo.InodesFree, *stats.InodesUsed)

	mockCadvisor.AssertExpectations(t)
}

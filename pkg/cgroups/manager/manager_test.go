// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"fmt"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ManagerSuite struct {
	mm *CgroupManager
}

var _ = Suite(&ManagerSuite{})

type cgroupMock struct {
	cgroupIds map[string]uint64
}

func (cg cgroupMock) GetCgroupID(cgroupPath string) (uint64, error) {
	if o, ok := cg.cgroupIds[cgroupPath]; ok {
		return o, nil
	}
	return 0, fmt.Errorf("")
}

type providerMock struct {
	paths map[string]string
}

func (pm providerMock) getContainerPath(podId string, containerId string, qos slimcorev1.PodQOSClass) (string, error) {
	return pm.paths[containerId], nil
}

func (pm providerMock) getBasePath() (string, error) {
	return "", nil

}

var (
	pod1IP         = slimcorev1.PodIP{IP: "1.2.3.4"}
	pod2IP         = slimcorev1.PodIP{IP: "5.6.7.8"}
	pod3IP         = slimcorev1.PodIP{IP: "7.8.7.8"}
	c1Id           = "d8f227cc24940cfdce8d8e601f3b92242ac9661b0e83f0ea57fdea1cb6bc93ec"
	c3Id           = "e8f227cc24940cfdce8d8e601f3b92242ac9661b0e83f0ea57fdea1cb6bc93ed"
	pod1C1CgrpPath = cgroupRoot + "/kubepods/burstable/pod1858680e-b044-4fd5-9dd4-f137e30e2180/" + c1Id
	pod2C1CgrpPath = cgroupRoot + "/kubepods/pod1858680e-b044-4fd5-9dd4-f137e30e2181/" + c3Id
	pod3C1CgrpPath = cgroupRoot + "/kubelet" + "/kubepods/burstable/pod2858680e-b044-4fd5-9dd4-f137e30e2180/" + c3Id
	pod3C2CgrpPath = cgroupRoot + "/kubelet" + "/kubepods/burstable/pod2858680e-b044-4fd5-9dd4-f137e30e2180/" + c1Id
	pod1Ips        = []slimcorev1.PodIP{pod1IP}
	pod2Ips        = []slimcorev1.PodIP{pod2IP}
	pod3Ips        = []slimcorev1.PodIP{pod3IP}
	pod1Ipstrs     = []string{pod1IP.IP}
	pod2Ipstrs     = []string{pod2IP.IP}
	pod3Ipstrs     = []string{pod3IP.IP}
	pod1           = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-p1",
			Namespace: "ns1",
			UID:       "1858680e-b044-4fd5-9dd4-f137e30e2180",
		},
		Spec: slimcorev1.PodSpec{
			NodeName: "n1",
		},
		Status: slimcorev1.PodStatus{
			PodIP:  pod1IP.IP,
			PodIPs: pod1Ips,
			ContainerStatuses: []slimcorev1.ContainerStatus{
				{
					ContainerID: "foo://" + c1Id,
					State:       slimcorev1.ContainerState{Running: &slimcorev1.ContainerStateRunning{}},
				},
			},
			QOSClass: slimcorev1.PodQOSBurstable,
		},
	}
	pod2 = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-p2",
			Namespace: "ns1",
			UID:       "1858680e-b044-4fd5-9dd4-f137e30e2181",
		},
		Spec: slimcorev1.PodSpec{
			NodeName: "n1",
		},
		Status: slimcorev1.PodStatus{
			PodIP:  pod2IP.IP,
			PodIPs: pod2Ips,
			ContainerStatuses: []slimcorev1.ContainerStatus{
				{
					ContainerID: "foo://" + c3Id,
					State:       slimcorev1.ContainerState{Running: &slimcorev1.ContainerStateRunning{}},
				},
			},
			QOSClass: slimcorev1.PodQOSGuaranteed,
		},
	}
	pod3 = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-p3",
			Namespace: "ns1",
			UID:       "2858680e-b044-4fd5-9dd4-f137e30e2180",
		},
		Spec: slimcorev1.PodSpec{
			NodeName: "n1",
		},
		Status: slimcorev1.PodStatus{
			PodIP:  pod3IP.IP,
			PodIPs: pod3Ips,
			ContainerStatuses: []slimcorev1.ContainerStatus{
				{
					ContainerID: "foo://" + c3Id,
					State:       slimcorev1.ContainerState{Running: &slimcorev1.ContainerStateRunning{}},
				},
			},
			QOSClass: slimcorev1.PodQOSBurstable,
		},
	}
)

func newCgroupManagerTest(pMock providerMock, cg cgroup) *CgroupManager {
	// Unbuffered channel tests to detect any issues on the caller side.
	return initManager(pMock, cg, 0)
}

func (m *ManagerSuite) SetUpTest(c *C) {
	option.Config.EnableSocketLBTracing = true
	nodetypes.SetName("n1")
}

func getFullPath(path string) string {
	return cgroupRoot + path
}

func (m *ManagerSuite) TestGetPodMetadataOnPodAdd(c *C) {
	c1CId := uint64(1234)
	c2CId := uint64(4567)
	c3CId := uint64(2345)
	cgMock := cgroupMock{cgroupIds: map[string]uint64{
		pod1C1CgrpPath: c1CId,
		pod2C1CgrpPath: c2CId,
	}}
	provMock := providerMock{paths: map[string]string{
		c1Id: pod1C1CgrpPath,
		c3Id: pod2C1CgrpPath,
	}}
	pod10 := pod1.DeepCopy()
	mm := newCgroupManagerTest(provMock, cgMock)

	type test struct {
		input  *slimcorev1.Pod
		cgrpId uint64
		want   *PodMetadata
	}

	// Add pods, and check for pod metadata for their containers.
	tests := []test{
		// Pod with Qos burstable.
		{input: pod1, cgrpId: c1CId, want: &PodMetadata{Name: pod1.Name, Namespace: pod1.Namespace, IPs: pod1Ipstrs}},
		// Pod with Qos guaranteed.
		{input: pod2, cgrpId: c2CId, want: &PodMetadata{Name: pod2.Name, Namespace: pod2.Namespace, IPs: pod2Ipstrs}},
		// Pod's container cgroup path doesn't exist.
		{input: pod10, cgrpId: c3CId, want: nil},
	}

	for _, tc := range tests {
		mm.OnAddPod(tc.input)

		got := mm.GetPodMetadataForContainer(tc.cgrpId)
		c.Assert(got, checker.Equals, tc.want)
	}
}
func (m *ManagerSuite) TestGetPodMetadataOnPodUpdate(c *C) {
	c3CId := uint64(2345)
	c1CId := uint64(1234)
	cgMock := cgroupMock{cgroupIds: map[string]uint64{
		pod3C1CgrpPath: c3CId,
		pod3C2CgrpPath: c1CId,
	}}
	provMock := providerMock{paths: map[string]string{
		c3Id: pod3C1CgrpPath,
		c1Id: pod3C2CgrpPath,
	}}
	mm := newCgroupManagerTest(provMock, cgMock)
	newPod := pod3.DeepCopy()
	cs := slimcorev1.ContainerStatus{
		State:       slimcorev1.ContainerState{Running: &slimcorev1.ContainerStateRunning{}},
		ContainerID: "foo://" + c1Id,
	}
	newPod.Status.ContainerStatuses = append(newPod.Status.ContainerStatuses, cs)

	// No pod added yet, so no pod metadata.
	got := mm.GetPodMetadataForContainer(c3CId)
	c.Assert(got, checker.Equals, (*PodMetadata)(nil))

	// Add pod, and check for pod metadata for their containers.
	mm.OnAddPod(pod3)

	got = mm.GetPodMetadataForContainer(c3CId)
	c.Assert(got, checker.Equals, &PodMetadata{Name: pod3.Name, Namespace: pod3.Namespace, IPs: pod3Ipstrs})

	// Update pod, and check for pod metadata for their containers.
	mm.OnUpdatePod(pod1, newPod)

	got1 := mm.GetPodMetadataForContainer(c3CId)
	got2 := mm.GetPodMetadataForContainer(c1CId)
	c.Assert(got1, checker.Equals, &PodMetadata{Name: pod3.Name, Namespace: pod3.Namespace, IPs: pod3Ipstrs})
	c.Assert(got2, checker.Equals, &PodMetadata{Name: pod3.Name, Namespace: pod3.Namespace, IPs: pod3Ipstrs})
}

func (m *ManagerSuite) TestGetPodMetadataOnManagerDisabled(c *C) {
	// Disable the feature flag.
	option.Config.EnableSocketLBTracing = false
	m.mm = newCgroupManagerTest(providerMock{}, cgroupMock{})
	c1CId := uint64(1234)

	m.mm.OnAddPod(pod1)

	got := m.mm.GetPodMetadataForContainer(c1CId)

	c.Assert(got, checker.Equals, (*PodMetadata)(nil))

	// Enable the feature flag, but the cgroup base path validation fails.
	option.Config.EnableSocketLBTracing = true
	m.mm.OnAddPod(pod1)

	got = m.mm.GetPodMetadataForContainer(c1CId)

	c.Assert(got, checker.Equals, (*PodMetadata)(nil))

}

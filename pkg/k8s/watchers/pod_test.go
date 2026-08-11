// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sAPITypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

type fakeEndpointManager struct {
	endpoints []*endpoint.Endpoint
}

func (*fakeEndpointManager) LookupCEPName(string) *endpoint.Endpoint { return nil }

func (m *fakeEndpointManager) GetEndpoints() []*endpoint.Endpoint { return m.endpoints }

func (*fakeEndpointManager) GetHostEndpoint() *endpoint.Endpoint { return nil }

func (m *fakeEndpointManager) GetEndpointsByPodName(string) []*endpoint.Endpoint {
	return m.endpoints
}

func (*fakeEndpointManager) WaitForEndpointsAtPolicyRev(context.Context, uint64) error { return nil }

func (*fakeEndpointManager) UpdatePolicyMaps(context.Context) error { return nil }

type fakeCgroupManager struct {
	addedPod   *slim_corev1.Pod
	deletedPod *slim_corev1.Pod
	operations []string
	updatedPod *slim_corev1.Pod
}

func (m *fakeCgroupManager) OnAddPod(pod *slim_corev1.Pod) {
	m.operations = append(m.operations, "add:"+string(pod.UID))
	m.addedPod = pod
}

func (m *fakeCgroupManager) OnUpdatePod(oldPod, newPod *slim_corev1.Pod) {
	if oldPod.UID != newPod.UID {
		m.operations = append(m.operations, "replace:"+string(oldPod.UID)+"->"+string(newPod.UID))
	} else {
		m.operations = append(m.operations, "update:"+string(newPod.UID))
	}
	m.updatedPod = newPod
}

func (m *fakeCgroupManager) OnDeletePod(pod *slim_corev1.Pod) {
	m.operations = append(m.operations, "delete:"+string(pod.UID))
	m.deletedPod = pod
}

type fakePolicyManager struct {
	reasons []string
}

func (m *fakePolicyManager) TriggerPolicyUpdates(reason string) {
	m.reasons = append(m.reasons, reason)
}

type ipcacheEvent struct {
	modType   ipcache.CacheModification
	oldHostIP string
	newHostIP string
	podUID    string
}

type recordingIPCacheListener struct {
	events []ipcacheEvent
}

func (l *recordingIPCacheListener) OnIPIdentityCacheChange(
	modType ipcache.CacheModification,
	_ cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP,
	_ *ipcache.Identity,
	_ ipcache.Identity,
	_ uint8,
	k8sMeta *ipcache.K8sMetadata,
	_ uint8,
) {
	event := ipcacheEvent{
		modType: modType,
	}
	if oldHostIP != nil {
		event.oldHostIP = oldHostIP.String()
	}
	if newHostIP != nil {
		event.newHostIP = newHostIP.String()
	}
	if k8sMeta != nil {
		event.podUID = k8sMeta.PodUID
	}
	l.events = append(l.events, event)
}

type fakeHostNetworkManager struct {
	addedPorts  [][]string
	addedPods   []k8sAPITypes.NamespacedName
	removedPods []k8sAPITypes.NamespacedName
	operations  []string
}

func (m *fakeHostNetworkManager) AddNoTrackHostPorts(namespace, name string, ports []string) {
	m.operations = append(m.operations, "add:"+namespace+"/"+name)
	m.addedPorts = append(m.addedPorts, slices.Clone(ports))
	m.addedPods = append(m.addedPods, k8sAPITypes.NamespacedName{
		Namespace: namespace,
		Name:      name,
	})
}

func (m *fakeHostNetworkManager) RemoveNoTrackHostPorts(namespace, name string) {
	m.operations = append(m.operations, "remove:"+namespace+"/"+name)
	m.removedPods = append(m.removedPods, k8sAPITypes.NamespacedName{
		Namespace: namespace,
		Name:      name,
	})
}

func TestAddK8sPodV1TracedHostNetworkPodAddsCgroupMetadata(t *testing.T) {
	oldTracing := option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing
	option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing = true
	t.Cleanup(func() {
		option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing = oldTracing
	})

	cgroups := &fakeCgroupManager{}
	hostNetwork := &fakeHostNetworkManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		cgroupManager:      cgroups,
		hostNetworkManager: hostNetwork,
	}
	pod := podWatcherTestPod("pod-uid", slim_corev1.PodRunning, "", "")
	pod.Spec.HostNetwork = true

	require.NoError(t, watcher.addK8sPodV1(t.Context(), pod))
	require.Equal(t, []string{"add:pod-uid"}, cgroups.operations)
	require.Equal(t, []string{"add:default/echo"}, hostNetwork.operations)
}

func TestReplaceK8sPodV1TerminalPodDeletesOldPodMetadata(t *testing.T) {
	const podIP = "10.0.0.1"

	ipc := newPodWatcherTestIPCache(t, podIP)
	cgroups := &fakeCgroupManager{}
	watcher := &K8sPodWatcher{
		logger:        hivetest.Logger(t),
		ipcache:       ipc,
		cgroupManager: cgroups,
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodSucceeded, podIP, "10.0.0.2")

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	_, exists := ipc.LookupByIP(podIP)
	require.False(t, exists)
	require.Same(t, oldPod, cgroups.deletedPod)
	require.Nil(t, cgroups.addedPod)
	require.Equal(t, []string{"delete:old-pod-uid"}, cgroups.operations)
}

func TestReplaceK8sPodV1TracedHostNetworkPodDeletesOldPodMetadata(t *testing.T) {
	const podIP = "10.0.0.1"
	oldTracing := option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing
	option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing = true
	t.Cleanup(func() {
		option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing = oldTracing
	})

	ipc := newPodWatcherTestIPCache(t, podIP)
	cgroups := &fakeCgroupManager{}
	hostNetwork := &fakeHostNetworkManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		ipcache:            ipc,
		cgroupManager:      cgroups,
		hostNetworkManager: hostNetwork,
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")
	newPod.Spec.HostNetwork = true

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	_, exists := ipc.LookupByIP(podIP)
	require.False(t, exists)
	require.Equal(t, []string{"replace:old-pod-uid->new-pod-uid"}, cgroups.operations)
	require.Equal(t, []string{"add:default/echo"}, hostNetwork.operations)
}

func TestReplaceK8sPodV1RemovesOldHostNetworkState(t *testing.T) {
	hostNetwork := &fakeHostNetworkManager{}
	cgroups := &fakeCgroupManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		cgroupManager:      cgroups,
		hostNetworkManager: hostNetwork,
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, "", "")
	oldPod.Spec.HostNetwork = true
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, "", "")

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	require.Equal(t, []k8sAPITypes.NamespacedName{
		{Namespace: "default", Name: "echo"},
	}, hostNetwork.removedPods)
	require.Equal(t, []string{"replace:old-pod-uid->new-pod-uid"}, cgroups.operations)
}

func TestReplaceK8sPodV1HostNetworkReplacementRefreshesState(t *testing.T) {
	hostNetwork := &fakeHostNetworkManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		cgroupManager:      &fakeCgroupManager{},
		hostNetworkManager: hostNetwork,
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, "", "")
	oldPod.Spec.HostNetwork = true
	oldPod.Annotations = map[string]string{annotation.NoTrackHostPorts: "80/tcp"}
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, "", "")
	newPod.Spec.HostNetwork = true
	newPod.Annotations = map[string]string{annotation.NoTrackHostPorts: "53/udp"}

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	pod := []k8sAPITypes.NamespacedName{{Namespace: "default", Name: "echo"}}
	require.Empty(t, hostNetwork.removedPods)
	require.Equal(t, pod, hostNetwork.addedPods)
	require.Equal(t, []string{"add:default/echo"}, hostNetwork.operations)
	require.Equal(t, [][]string{{"53/udp"}}, hostNetwork.addedPorts)
}

func TestValidNoTrackHostPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports []string
		want  bool
	}{
		{name: "empty", ports: []string{""}, want: true},
		{name: "TCP", ports: []string{"80/tcp"}, want: true},
		{name: "UDP", ports: []string{"53/udp"}, want: true},
		{name: "multiple", ports: []string{"80/tcp", "53/udp"}, want: true},
		{name: "malformed", ports: []string{"invalid"}},
		{name: "unsupported protocol", ports: []string{"80/sctp"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, validNoTrackHostPorts(tt.ports))
		})
	}
}

func TestReplaceK8sPodV1InvalidHostNetworkReplacementRemovesOldState(t *testing.T) {
	hostNetwork := &fakeHostNetworkManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		cgroupManager:      &fakeCgroupManager{},
		hostNetworkManager: hostNetwork,
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, "", "")
	oldPod.Spec.HostNetwork = true
	oldPod.Annotations = map[string]string{annotation.NoTrackHostPorts: "80/tcp"}
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, "", "")
	newPod.Spec.HostNetwork = true
	newPod.Annotations = map[string]string{annotation.NoTrackHostPorts: "invalid"}

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	require.Equal(t, []string{
		"remove:default/echo",
		"add:default/echo",
	}, hostNetwork.operations)
	require.Equal(t, [][]string{{"invalid"}}, hostNetwork.addedPorts)
}

func TestReplaceK8sPodV1InvalidHostIPRecoversOnPodUpdate(t *testing.T) {
	const podIP = "10.0.0.1"

	ipc := newPodWatcherTestIPCache(t, podIP)
	_, err := ipc.Upsert(podIP, nil, 0, &ipcache.K8sMetadata{
		Namespace: "default",
		PodName:   "echo",
		PodUID:    "old-pod-uid",
		NamedPorts: ciliumTypes.NamedPortMap{
			"http": {Port: 80, Proto: u8proto.TCP},
		},
	}, ipcache.Identity{
		ID:     identity.ReservedIdentityUnmanaged,
		Source: source.Kubernetes,
	})
	require.NoError(t, err)
	ipc.GetNamedPorts()

	cgroups := &fakeCgroupManager{}
	policies := &fakePolicyManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		policyManager:      policies,
		ipcache:            ipc,
		cgroupManager:      cgroups,
		hostNetworkManager: &fakeHostNetworkManager{},
		localNodeStore:     node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:           fakewireguard.Config{},
		ipsecConfig:        fakeipsec.Config{},
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, podIP, "")

	err = watcher.replaceK8sPodV1(t.Context(), oldPod, newPod)
	require.ErrorContains(t, err, "no/invalid HostIP")
	_, exists := ipc.LookupByIP(podIP)
	require.False(t, exists)
	require.Len(t, policies.reasons, 1)
	require.Equal(t, []string{"replace:old-pod-uid->new-pod-uid"}, cgroups.operations)

	recoveredPod := newPod.DeepCopy()
	recoveredPod.Status.HostIP = "10.0.0.2"
	require.NoError(t, watcher.updateExistingK8sPodV1(t.Context(), newPod, recoveredPod))
	metadata := ipc.GetK8sMetadata(netip.MustParseAddr(podIP))
	require.NotNil(t, metadata)
	require.Equal(t, string(recoveredPod.UID), metadata.PodUID)
	require.Equal(t, []string{
		"replace:old-pod-uid->new-pod-uid",
		"update:new-pod-uid",
	}, cgroups.operations)
}

func TestReplaceK8sPodV1KeepsNewPodMetadata(t *testing.T) {
	const podIP = "10.0.0.1"

	ipc := newPodWatcherTestIPCache(t, podIP)
	listener := &recordingIPCacheListener{}
	ipc.AddListener(listener)
	// Ignore the current-state dump performed when a listener is registered.
	listener.events = nil
	cgroups := &fakeCgroupManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		ipcache:            ipc,
		cgroupManager:      cgroups,
		hostNetworkManager: &fakeHostNetworkManager{},
		localNodeStore:     node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:           fakewireguard.Config{},
		ipsecConfig:        fakeipsec.Config{},
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	metadata := ipc.GetK8sMetadata(netip.MustParseAddr(podIP))
	require.NotNil(t, metadata)
	require.Equal(t, string(newPod.UID), metadata.PodUID)
	require.Equal(t, []string{"replace:old-pod-uid->new-pod-uid"}, cgroups.operations)
	require.Equal(t, []ipcacheEvent{{
		modType:   ipcache.Upsert,
		newHostIP: "10.0.0.2",
		podUID:    "new-pod-uid",
	}}, listener.events)
}

func TestReplaceK8sPodV1SameIPChangedHostUpdatesInPlace(t *testing.T) {
	const (
		podIP     = "10.0.0.1"
		oldHostIP = "10.0.0.2"
		newHostIP = "10.0.0.3"
	)

	ipc := newPodWatcherTestIPCache(t, podIP)
	_, err := ipc.Upsert(podIP, net.ParseIP(oldHostIP), 0, &ipcache.K8sMetadata{
		Namespace: "default",
		PodName:   "echo",
		PodUID:    "old-pod-uid",
	}, ipcache.Identity{
		ID:     identity.ReservedIdentityUnmanaged,
		Source: source.Kubernetes,
	})
	require.NoError(t, err)
	listener := &recordingIPCacheListener{}
	ipc.AddListener(listener)
	listener.events = nil // Ignore the listener's initial current-state dump.
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		ipcache:            ipc,
		cgroupManager:      &fakeCgroupManager{},
		hostNetworkManager: &fakeHostNetworkManager{},
		localNodeStore:     node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:           fakewireguard.Config{},
		ipsecConfig:        fakeipsec.Config{},
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, podIP, oldHostIP)
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, podIP, newHostIP)

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	require.Equal(t, []ipcacheEvent{{
		modType:   ipcache.Upsert,
		oldHostIP: oldHostIP,
		newHostIP: newHostIP,
		podUID:    "new-pod-uid",
	}}, listener.events)
}

func TestReplaceK8sPodV1PublishesNewIPBeforeDeletingOldIP(t *testing.T) {
	const (
		oldPodIP = "10.0.0.1"
		newPodIP = "10.0.0.2"
	)

	ipc := newPodWatcherTestIPCache(t, oldPodIP)
	listener := &recordingIPCacheListener{}
	ipc.AddListener(listener)
	listener.events = nil // Ignore the listener's initial current-state dump.
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		ipcache:            ipc,
		cgroupManager:      &fakeCgroupManager{},
		hostNetworkManager: &fakeHostNetworkManager{},
		localNodeStore:     node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:           fakewireguard.Config{},
		ipsecConfig:        fakeipsec.Config{},
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, oldPodIP, "10.0.0.3")
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, newPodIP, "10.0.0.3")

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	require.Equal(t, []ipcacheEvent{
		{modType: ipcache.Upsert, newHostIP: "10.0.0.3", podUID: "new-pod-uid"},
		{modType: ipcache.Delete, podUID: "old-pod-uid"},
	}, listener.events)
}

func TestReplaceK8sPodV1CoalescesNamedPortPolicyUpdate(t *testing.T) {
	const podIP = "10.0.0.1"

	ipc := newPodWatcherTestIPCache(t, podIP)
	_, err := ipc.Upsert(podIP, nil, 0, &ipcache.K8sMetadata{
		Namespace: "default",
		PodName:   "echo",
		PodUID:    "old-pod-uid",
		NamedPorts: ciliumTypes.NamedPortMap{
			"http": {Port: 80, Proto: u8proto.TCP},
		},
	}, ipcache.Identity{
		ID:     identity.ReservedIdentityUnmanaged,
		Source: source.Kubernetes,
	})
	require.NoError(t, err)
	ipc.GetNamedPorts()

	policies := &fakePolicyManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		policyManager:      policies,
		ipcache:            ipc,
		cgroupManager:      &fakeCgroupManager{},
		hostNetworkManager: &fakeHostNetworkManager{},
		localNodeStore:     node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:           fakewireguard.Config{},
		ipsecConfig:        fakeipsec.Config{},
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")
	newPod.Spec.Containers = []slim_corev1.Container{{
		Ports: []slim_corev1.ContainerPort{{
			Name:          "http",
			ContainerPort: 8080,
			Protocol:      slim_corev1.ProtocolTCP,
		}},
	}}

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	require.Len(t, policies.reasons, 1)
	port, err := ipc.GetNamedPorts().GetNamedPort(
		"http",
		u8proto.TCP,
		slices.Values([]identity.NumericIdentity{identity.ReservedIdentityUnmanaged}),
	)
	require.NoError(t, err)
	require.Equal(t, uint16(8080), port)
}

func TestReplaceK8sPodV1MissingOldMetadataStillAddsNewPod(t *testing.T) {
	const podIP = "10.0.0.1"

	ipc := newPodWatcherTestIPCache(t, podIP)
	ipc.Delete(podIP, source.Kubernetes)
	cgroups := &fakeCgroupManager{}
	watcher := &K8sPodWatcher{
		logger:             hivetest.Logger(t),
		endpointManager:    &fakeEndpointManager{},
		ipcache:            ipc,
		cgroupManager:      cgroups,
		hostNetworkManager: &fakeHostNetworkManager{},
		localNodeStore:     node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:           fakewireguard.Config{},
		ipsecConfig:        fakeipsec.Config{},
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, podIP, "10.0.0.2")

	require.NoError(t, watcher.replaceK8sPodV1(t.Context(), oldPod, newPod))
	metadata := ipc.GetK8sMetadata(netip.MustParseAddr(podIP))
	require.NotNil(t, metadata)
	require.Equal(t, string(newPod.UID), metadata.PodUID)
	require.Equal(t, []string{"replace:old-pod-uid->new-pod-uid"}, cgroups.operations)
}

func TestReplaceK8sPodV1ReconcilesEndpointLabels(t *testing.T) {
	logger := hivetest.Logger(t)
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(logger, nil, nil, ""))
	repo := policy.NewPolicyRepository(
		logger,
		nil,
		nil,
		nil,
		nil,
		testpolicy.NewPolicyMetricsNoop(),
	)
	state := models.EndpointStateWaitingDashForDashIdentity
	ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
		Logger:     logger,
		PolicyRepo: repo,
	}, nil, nil, &models.EndpointChangeRequest{State: &state}, nil)
	require.NoError(t, err)
	require.True(t, ep.SetState(endpoint.StateDisconnecting, "test replacement reconciliation"))

	watcher := &K8sPodWatcher{
		logger:             logger,
		endpointManager:    &fakeEndpointManager{endpoints: []*endpoint.Endpoint{ep}},
		cgroupManager:      &fakeCgroupManager{},
		hostNetworkManager: &fakeHostNetworkManager{},
	}
	oldPod := podWatcherTestPod("old-pod-uid", slim_corev1.PodRunning, "", "")
	oldPod.Labels = map[string]string{"app": "echo"}
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, "", "")
	newPod.Labels = map[string]string{"app": "echo"}

	err = watcher.replaceK8sPodV1(t.Context(), oldPod, newPod)
	require.ErrorIs(t, err, endpoint.ErrNotAlive)
}

func TestUpdatePodHostDataWithoutOldPodDoesNotDeleteUnownedMetadata(t *testing.T) {
	const (
		oldPodIP = "10.0.0.1"
		newPodIP = "10.0.0.2"
	)

	ipc := newPodWatcherTestIPCache(t, oldPodIP)
	watcher := &K8sPodWatcher{
		logger:         hivetest.Logger(t),
		policyManager:  &fakePolicyManager{},
		ipcache:        ipc,
		localNodeStore: node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:       fakewireguard.Config{},
		ipsecConfig:    fakeipsec.Config{},
	}
	newPod := podWatcherTestPod("new-pod-uid", slim_corev1.PodRunning, newPodIP, "10.0.0.3")

	require.NoError(t, watcher.updatePodHostData(
		t.Context(),
		nil,
		newPod,
		k8sTypes.IPSlice{oldPodIP},
		k8sTypes.IPSlice{newPodIP},
	))
	_, oldExists := ipc.LookupByIP(oldPodIP)
	_, newExists := ipc.LookupByIP(newPodIP)
	require.True(t, oldExists)
	require.True(t, newExists)
}

func newPodWatcherTestIPCache(t *testing.T, podIP string) *ipcache.IPCache {
	t.Helper()

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: t.Context(),
		Logger:  hivetest.Logger(t),
	})
	t.Cleanup(func() {
		require.NoError(t, ipc.Shutdown())
	})

	_, err := ipc.Upsert(podIP, nil, 0, &ipcache.K8sMetadata{
		Namespace: "default",
		PodName:   "echo",
		PodUID:    "old-pod-uid",
	}, ipcache.Identity{
		ID:     identity.ReservedIdentityUnmanaged,
		Source: source.Kubernetes,
	})
	require.NoError(t, err)

	return ipc
}

func podWatcherTestPod(uid string, phase slim_corev1.PodPhase, podIP, hostIP string) *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: "default",
			Name:      "echo",
			UID:       k8sAPITypes.UID(uid),
		},
		Status: slim_corev1.PodStatus{
			Phase:  phase,
			PodIP:  podIP,
			PodIPs: []slim_corev1.PodIP{{IP: podIP}},
			HostIP: hostIP,
		},
	}
}

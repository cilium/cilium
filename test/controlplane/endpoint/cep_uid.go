// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/common"
	pkgendpoint "github.com/cilium/cilium/pkg/endpoint"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	fakepolicymap "github.com/cilium/cilium/pkg/maps/policymap/fake"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func init() {
	suite.AddTestCase("EndpointCEPUIDPersistence", func(t *testing.T) {
		k8sVersions := controlplane.K8sVersions()
		version := k8sVersions[len(k8sVersions)-1]

		t.Run("persists recreated CEP UID to disk and restores across agent restart", func(t *testing.T) {
			runCEPUIDRestartPersistenceTest(t, version, false)
		})

		t.Run("reclaims recreated CEP UID after ungraceful restart with stale state on disk", func(t *testing.T) {
			runCEPUIDRestartPersistenceTest(t, version, true)
		})
	})
}

type fakePolicyMapFactory struct{}

func (*fakePolicyMapFactory) OpenEndpoint(uint16) (policymap.PolicyMap, error) {
	return fakepolicymap.NewFakePolicyMap(), nil
}
func (*fakePolicyMapFactory) RemoveEndpoint(uint16) error      { return nil }
func (*fakePolicyMapFactory) RemoveGlobalMapping(uint32) error { return nil }
func (*fakePolicyMapFactory) PolicyMaxEntries() int            { return 0 }
func (*fakePolicyMapFactory) StatsMaxEntries() int             { return 0 }

type fakeLXCMap struct{}

func (*fakeLXCMap) WriteEndpoint(lxcmap.EndpointFrontend) error                 { return nil }
func (*fakeLXCMap) SyncHostEntry(netip.Addr) (bool, error)                      { return false, nil }
func (*fakeLXCMap) DeleteEntry(netip.Addr) error                                { return nil }
func (*fakeLXCMap) DeleteElement(*slog.Logger, lxcmap.EndpointFrontend) []error { return nil }
func (*fakeLXCMap) Dump(map[string][]string) error                              { return nil }
func (*fakeLXCMap) DumpToMap() (map[netip.Addr]lxcmap.EndpointInfo, error)      { return nil, nil }

type agentDeps struct {
	cs          k8sClient.Clientset
	epMgr       endpointmanager.EndpointManager
	epCreator   endpointcreator.EndpointCreator
	epMetadata  endpointmetadata.EndpointMetadataFetcher
	regenerator *pkgendpoint.Regenerator
	lns         *node.LocalNodeStore
	logger      *slog.Logger
}

func runCEPUIDRestartPersistenceTest(t *testing.T, version string, simulateCrashBeforeSync bool) {
	const (
		nodeName  = "worker-1"
		nodeIP    = "10.0.0.10"
		namespace = "default"
		podName   = "test-pod"
		podUID    = types.UID("pod-uid-1")
		cniAttach = "sandbox-1"
	)

	nodeObj := &corev1.Node{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Node",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			Labels: map[string]string{
				"kubernetes.io/hostname": nodeName,
				"kubernetes.io/os":       "linux",
			},
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  "10.244.0.0/24",
			PodCIDRs: []string{"10.244.0.0/24"},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: nodeIP},
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourcePods: resource.MustParse("110"),
			},
		},
	}

	defaultNS := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Namespace",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}

	podObj := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			UID:       podUID,
			Labels:    map[string]string{"app": "cep-uid-test"},
		},
		Spec: corev1.PodSpec{
			NodeName:           nodeName,
			ServiceAccountName: "sa-initial",
		},
		Status: corev1.PodStatus{
			HostIP: nodeIP,
			PodIP:  "10.244.0.5",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}

	slimPod := func(sa string) *slim_corev1.Pod {
		return &slim_corev1.Pod{
			TypeMeta: slim_metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      podName,
				Namespace: namespace,
				UID:       podUID,
				Labels:    map[string]string{"app": "cep-uid-test"},
			},
			Spec: slim_corev1.PodSpec{
				ServiceAccountName: sa,
			},
			Status: slim_corev1.PodStatus{
				HostIP: nodeIP,
			},
		}
	}

	readPersistedCEPUID := func(stateDir string, epID uint16) (types.UID, error) {
		raw, err := os.ReadFile(filepath.Join(stateDir, fmt.Sprintf("%d", epID), common.EndpointStateFileName))
		if err != nil {
			return "", err
		}
		var state struct {
			CiliumEndpointUID types.UID `json:"CiliumEndpointUID"`
		}
		if err := json.Unmarshal(raw, &state); err != nil {
			return "", err
		}
		return state.CiliumEndpointUID, nil
	}

	modConfig := func(cfg *option.DaemonConfig) {
		cfg.RestoreState = false
		cfg.EnableCiliumEndpointSlice = false
	}

	test := suite.NewControlPlaneTest(t, nodeName, version)
	var deps1 agentDeps
	var reactorsInstalled bool
	var createCount atomic.Int32
	var revCount atomic.Int32

	grabCell := func(target *agentDeps) cell.Cell {
		return cell.Invoke(func(
			cs k8sClient.Clientset,
			epMgr endpointmanager.EndpointManager,
			epCreator endpointcreator.EndpointCreator,
			epMetadata endpointmetadata.EndpointMetadataFetcher,
			regenerator *pkgendpoint.Regenerator,
			lns *node.LocalNodeStore,
			logger *slog.Logger,
		) {
			target.cs = cs
			target.epMgr = epMgr
			target.epCreator = epCreator
			target.epMetadata = epMetadata
			target.regenerator = regenerator
			target.lns = lns
			target.logger = logger

			if !reactorsInstalled {
				reactorsInstalled = true
				fakeCS := cs.(*k8sFakeClient.FakeClientset)
				fakeCS.CiliumFakeClientset.PrependReactor("create", "ciliumendpoints",
					func(action k8stesting.Action) (bool, runtime.Object, error) {
						createAction := action.(k8stesting.CreateAction)
						cep := createAction.GetObject().(*cilium_v2.CiliumEndpoint)
						n := createCount.Add(1)
						cep.UID = types.UID(fmt.Sprintf("cep-uid-%d", n))
						cep.ResourceVersion = fmt.Sprintf("%d", revCount.Add(1))
						return false, cep, nil
					},
				)
				fakeCS.CiliumFakeClientset.PrependReactor("patch", "ciliumendpoints",
					func(action k8stesting.Action) (bool, runtime.Object, error) {
						patchAction := action.(k8stesting.PatchAction)
						existing, err := fakeCS.CiliumFakeClientset.Tracker().Get(
							cilium_v2.SchemeGroupVersion.WithResource("ciliumendpoints"),
							patchAction.GetNamespace(),
							patchAction.GetName(),
						)
						if err == nil {
							existing.(*cilium_v2.CiliumEndpoint).ResourceVersion = fmt.Sprintf("%d", revCount.Add(1))
						}
						return false, nil, nil
					},
				)
			}
		})
	}

	var agentRunning bool
	startAgent := func(target *agentDeps) {
		agentRunning = true
		test.StartAgent(
			modConfig,
			cell.DecorateAll(func(policymap.Factory, lxcmap.Map) (policymap.Factory, lxcmap.Map) {
				return &fakePolicyMapFactory{}, &fakeLXCMap{}
			}),
			grabCell(target),
		).EnsureWatchers("nodes", "pods", "namespaces")
	}
	stopAgent := func() {
		if agentRunning {
			agentRunning = false
			test.StopAgent()
		}
	}
	origWD, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Chdir(origWD)
		stopAgent()
		test.ClearEnvironment()
	})

	// Phase 1: Start first agent instance, create endpoint, persist CEP UID ("cep-uid-1").
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(slog.New(slog.DiscardHandler), nil, nil, ""))
	test.
		UpdateObjects(nodeObj, defaultNS, podObj).
		SetupEnvironment()
	startAgent(&deps1)
	require.NoError(t, os.Chdir(option.Config.StateDir))

	test.Eventually(func() error {
		ln, err := deps1.lns.Get(t.Context())
		if err != nil {
			return err
		}
		if ln.Name != nodeName {
			return fmt.Errorf("local node not ready: %+v", ln)
		}
		return nil
	})

	ep1, err := deps1.epCreator.NewEndpointFromChangeModel(&models.EndpointChangeRequest{
		K8sPodName:   podName,
		K8sNamespace: namespace,
		K8sUID:       string(podUID),
		ContainerID:  cniAttach,
		State:        ptr.To(models.EndpointStateWaitingDashForDashIdentity),
		Addressing: &models.AddressPair{
			IPv4: "10.244.0.5",
		},
	})
	require.NoError(t, err)
	require.NoError(t, deps1.epMgr.AddEndpoint(ep1))
	epID := ep1.ID
	require.NoError(t, os.MkdirAll(ep1.StateDirectoryPath(), 0o777))
	ep1.SetK8sMetadata(nil)
	ep1.SetPod(slimPod("sa-initial"))
	ep1.UpdateLabels(t.Context(), labels.LabelSourceK8s,
		labels.Map2Labels(map[string]string{"app": "cep-uid-test"}, labels.LabelSourceK8s),
		nil, true,
	)

	var cepStatus *cilium_v2.EndpointStatus
	stateDir := option.Config.StateDir
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, ep1.GetIdentity())
		cep, getErr := deps1.cs.CiliumV2().CiliumEndpoints(namespace).Get(t.Context(), podName, metav1.GetOptions{})
		if assert.NoError(c, getErr) {
			assert.Equal(c, types.UID("cep-uid-1"), cep.UID)
			cepStatus = cep.Status.DeepCopy()
		}
		assert.Equal(c, types.UID("cep-uid-1"), ep1.GetCiliumEndpointUID())
		uidOnDisk, diskErr := readPersistedCEPUID(stateDir, epID)
		if assert.NoError(c, diskErr) {
			assert.Equal(c, types.UID("cep-uid-1"), uidOnDisk)
		}
	}, 15*time.Second, 50*time.Millisecond)
	idBefore := ep1.GetIdentity()

	// Phase 2: External actor deletes and recreates CEP with a new UID ("cep-uid-2").
	recreateCEP := func(ownerUID types.UID) *cilium_v2.CiliumEndpoint {
		require.NoError(t, deps1.cs.CiliumV2().CiliumEndpoints(namespace).Delete(t.Context(), podName, metav1.DeleteOptions{}))
		created, createErr := deps1.cs.CiliumV2().CiliumEndpoints(namespace).Create(t.Context(), &cilium_v2.CiliumEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "v1",
						Kind:       "Pod",
						Name:       podName,
						UID:        ownerUID,
					},
				},
			},
			Status: *cepStatus,
		}, metav1.CreateOptions{})
		require.NoError(t, createErr)
		return created
	}

	if !simulateCrashBeforeSync {
		recreated := recreateCEP(podUID)
		require.Equal(t, types.UID("cep-uid-2"), recreated.UID)

		// Trigger a status change on ep1 so the synchronizer hits UID test precondition failure,
		// enters needInit -> updateCEPUID -> adopts cep-uid-2 -> flushes ep_config.json to disk.
		ep1.SetPod(slimPod("sa-recreated-before-restart"))
		ep1.UpdateLabels(t.Context(), labels.LabelSourceK8s,
			labels.Map2Labels(map[string]string{"app": "cep-uid-test", "phase": "recreated"}, labels.LabelSourceK8s),
			nil, false,
		)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Equal(c, types.UID("cep-uid-2"), ep1.GetCiliumEndpointUID())
			uidOnDisk, diskErr := readPersistedCEPUID(stateDir, epID)
			if assert.NoError(c, diskErr) {
				assert.Equal(c, types.UID("cep-uid-2"), uidOnDisk)
			}
			cep, getErr := deps1.cs.CiliumV2().CiliumEndpoints(namespace).Get(t.Context(), podName, metav1.GetOptions{})
			if assert.NoError(c, getErr) {
				assert.Equal(c, "sa-recreated-before-restart", cep.Status.ServiceAccount)
			}
		}, 15*time.Second, 50*time.Millisecond)
	}

	// Stop Agent 1 while preserving StateDir and FakeClientset.
	stopAgent()

	if simulateCrashBeforeSync {
		// CEP was recreated while ep_config.json on disk still holds stale "cep-uid-1".
		recreated := recreateCEP(podUID)
		require.Equal(t, types.UID("cep-uid-2"), recreated.UID)
		uidOnDisk, diskErr := readPersistedCEPUID(stateDir, epID)
		require.NoError(t, diskErr)
		require.Equal(t, types.UID("cep-uid-1"), uidOnDisk)
	}

	// Update the Pod spec & labels before Agent 2 starts so restored metadata resolver observes them.
	podAfterRestart := podObj.DeepCopy()
	podAfterRestart.Spec.ServiceAccountName = "sa-after-restart"
	podAfterRestart.Labels["restarted"] = "true"
	test.UpdateObjects(podAfterRestart)

	// Phase 3: Start Agent 2 on the same StateDir & FakeClientset and restore endpoints from disk.
	var deps2 agentDeps
	startAgent(&deps2)

	eps, failed := pkgendpoint.ReadEPsFromDirNames(t.Context(), deps2.logger, deps2.epCreator, stateDir, []string{fmt.Sprintf("%d", epID)})
	require.Zero(t, failed)
	restoredEP, ok := eps[epID]
	require.True(t, ok, "expected endpoint %d to be restored from %s", epID, stateDir)

	if !simulateCrashBeforeSync {
		require.Equal(t, types.UID("cep-uid-2"), restoredEP.GetCiliumEndpointUID())
	} else {
		require.Equal(t, types.UID("cep-uid-1"), restoredEP.GetCiliumEndpointUID())
	}

	test.Eventually(func() error {
		pod, _, fetchErr := deps2.epMetadata.FetchK8sMetadataForEndpoint(namespace, podName, string(podUID), false)
		if fetchErr != nil {
			return fetchErr
		}
		if pod.Labels["restarted"] != "true" {
			return fmt.Errorf("restored pod labels not synced yet: %+v", pod.Labels)
		}
		return nil
	})

	restoredEP.SetDefaultConfiguration()
	restoredEP.SkipStateClean()
	require.NoError(t, deps2.epMgr.RestoreEndpoint(restoredEP))
	require.NoError(t, restoredEP.RegenerateAfterRestore(deps2.regenerator, deps2.epMetadata.FetchK8sMetadataForEndpoint))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		idAfter := restoredEP.GetIdentity()
		assert.NotZero(c, idAfter)
		assert.NotEqual(c, idBefore, idAfter)
		assert.Equal(c, types.UID("cep-uid-2"), restoredEP.GetCiliumEndpointUID())
		cep, getErr := deps2.cs.CiliumV2().CiliumEndpoints(namespace).Get(t.Context(), podName, metav1.GetOptions{})
		if assert.NoError(c, getErr) {
			assert.Equal(c, types.UID("cep-uid-2"), cep.UID)
			assert.Equal(c, "sa-after-restart", cep.Status.ServiceAccount)
			if assert.NotNil(c, cep.Status.Identity) {
				assert.Equal(c, int64(idAfter), cep.Status.Identity.ID)
			}
		}
		uidOnDisk, diskErr := readPersistedCEPUID(stateDir, epID)
		if assert.NoError(c, diskErr) {
			assert.Equal(c, types.UID("cep-uid-2"), uidOnDisk)
		}
	}, 20*time.Second, 50*time.Millisecond)

	// Negative boundary: if a recreated CEP belongs to a different Pod UID (rescheduled pod),
	// removing this endpoint must not delete the foreign CEP.
	foreignCEP := recreateCEP(types.UID("pod-uid-foreign"))
	require.Equal(t, types.UID("cep-uid-3"), foreignCEP.UID)

	restoredEP.SetPropertyValue(endpointtypes.PropertyFakeEndpoint, true)
	errs := deps2.epMgr.RemoveEndpoint(restoredEP, pkgendpoint.DeleteConfig{
		NoIdentityRelease: true,
		NoIPRelease:       true,
	})
	require.Empty(t, errs)

	// Give StopFunc controller a brief window, then confirm foreign CEP cep-uid-3 remains untouched
	// after cleanup, while owner Pod UID "pod-uid-1" deletion would not hijack "pod-uid-foreign".
	time.Sleep(100 * time.Millisecond)
	stillPresent, getErr := deps2.cs.CiliumV2().CiliumEndpoints(namespace).Get(t.Context(), podName, metav1.GetOptions{})
	require.NoError(t, getErr)
	require.Equal(t, types.UID("cep-uid-3"), stillPresent.UID)

	// Clean up agent cleanly before ClearEnvironment runs.
	stopAgent()
}

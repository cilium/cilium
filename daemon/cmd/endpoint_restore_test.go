// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/endpoint"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedRemoveStaleEPIfaces(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "lxc12345"
		veth := &netlink.Veth{
			LinkAttrs: linkAttrs,
			PeerName:  "tmp54321",
		}

		err := netlink.LinkAdd(veth)
		assert.NoError(t, err)

		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.NoError(t, err)

		restorer := &endpointRestorer{logger: hivetest.Logger(t)}
		err = restorer.clearStaleCiliumEndpointVeths()
		assert.NoError(t, err)

		// Check that stale iface is removed
		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.Error(t, err)

		return nil
	})
}

type fakeK8sWatcher struct {
	pod *slim_corev1.Pod
	err error
}

func (f *fakeK8sWatcher) WaitForCacheSync(resourceNames ...string) {}

func (f *fakeK8sWatcher) GetCachedPod(namespace, name string) (*slim_corev1.Pod, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.pod == nil {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Group: "core", Resource: "pod"}, name)
	}
	return f.pod, nil
}

func TestGetPodForEndpoint(t *testing.T) {
	ctx := context.Background()
	nodeName := "node-1"
	ep := &endpoint.Endpoint{
		K8sPodName:   "pod-1",
		K8sNamespace: "ns-1",
	}
	nodeTypes.SetName(nodeName)

	t.Run("Pod found in cache", func(t *testing.T) {
		pod := &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "pod-1",
				Namespace: "ns-1",
			},
			Spec: slim_corev1.PodSpec{
				NodeName: nodeName,
			},
		}
		watcher := &fakeK8sWatcher{pod: pod}
		_, clientset := k8sClient.NewFakeClientset(hivetest.Logger(t))

		restorer := &endpointRestorer{
			ctx:        ctx,
			k8sWatcher: watcher,
			clientset:  clientset,
		}

		err := restorer.getPodForEndpoint(ep)
		require.NoError(t, err)
	})

	t.Run("Pod not in cache, found in API server", func(t *testing.T) {
		pod := &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "pod-1",
				Namespace: "ns-1",
			},
			Spec: slim_corev1.PodSpec{
				NodeName: nodeName,
			},
		}
		watcher := &fakeK8sWatcher{}
		fc, clientset := k8sClient.NewFakeClientset(hivetest.Logger(t))
		fc.SlimFakeClientset.Tracker().Add(pod)

		restorer := &endpointRestorer{
			ctx:        ctx,
			k8sWatcher: watcher,
			clientset:  clientset,
		}

		err := restorer.getPodForEndpoint(ep)
		require.NoError(t, err)
	})

	t.Run("Pod not found in cache nor API server", func(t *testing.T) {
		watcher := &fakeK8sWatcher{}
		_, clientset := k8sClient.NewFakeClientset(hivetest.Logger(t))

		restorer := &endpointRestorer{
			ctx:        ctx,
			k8sWatcher: watcher,
			clientset:  clientset,
		}

		err := restorer.getPodForEndpoint(ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not exist")
	})

	t.Run("Pod in cache but not owned by this node", func(t *testing.T) {
		pod := &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "pod-1",
				Namespace: "ns-1",
			},
			Spec: slim_corev1.PodSpec{
				NodeName: "node-2",
			},
		}
		watcher := &fakeK8sWatcher{pod: pod}
		_, clientset := k8sClient.NewFakeClientset(hivetest.Logger(t))

		restorer := &endpointRestorer{
			ctx:        ctx,
			k8sWatcher: watcher,
			clientset:  clientset,
		}

		err := restorer.getPodForEndpoint(ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "is not owned by this agent")
	})

	t.Run("Unexpected error in GetCachedPod is returned", func(t *testing.T) {
		watcher := &fakeK8sWatcher{err: errors.New("unexpected error")}
		_, clientset := k8sClient.NewFakeClientset(hivetest.Logger(t))

		restorer := &endpointRestorer{
			ctx:        ctx,
			k8sWatcher: watcher,
			clientset:  clientset,
		}

		err := restorer.getPodForEndpoint(ep)
		require.Error(t, err)
		require.Equal(t, "unexpected error", err.Error())
	})
}

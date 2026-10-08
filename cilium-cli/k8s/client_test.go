// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/moby/spdystream"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestAutodetectFlavorGKE(t *testing.T) {
	t.Run("by-cluster-name", func(t *testing.T) {
		c := &Client{
			Clientset: fake.NewSimpleClientset(),
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"gke_project_zone_cluster": {
						Cluster: "gke_project_zone_cluster",
					},
				},
				CurrentContext: "gke_project_zone_cluster",
			},
			contextName: "gke_project_zone_cluster",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindGKE, flavor.Kind)
	})

	t.Run("by-node-label", func(t *testing.T) {
		k8sClient := fake.NewSimpleClientset(
			&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gke-node-1",
					Labels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				},
			},
		)

		c := &Client{
			Clientset: k8sClient,
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"my-cluster": {
						Cluster: "my-cluster",
					},
				},
				CurrentContext: "my-cluster",
			},
			contextName: "my-cluster",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindGKE, flavor.Kind, "Should detect GKE via node label")
	})
}

func TestAutodetectFlavorEKS(t *testing.T) {
	t.Run("by-cluster-name", func(t *testing.T) {
		c := &Client{
			Clientset: fake.NewSimpleClientset(),
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"foo.us-west-2.eksctl.io": {
						Cluster: "foo.us-west-2.eksctl.io",
					},
				},
				CurrentContext: "foo.us-west-2.eksctl.io",
			},
			contextName: "foo.us-west-2.eksctl.io",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindEKS, flavor.Kind)
	})

	t.Run("by-cluster-server", func(t *testing.T) {
		c := &Client{
			Clientset: fake.NewSimpleClientset(),
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"my-cluster": {
						Cluster: "my-cluster",
					},
				},
				Clusters: map[string]*clientcmdapi.Cluster{
					"my-cluster": {
						Server: "https://ABCDEF1234567890.gr7.us-west-2.eks.amazonaws.com",
					},
				},
				CurrentContext: "my-cluster",
			},
			contextName: "my-cluster",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindEKS, flavor.Kind, "Should detect EKS via cluster server URL")
	})

	t.Run("by-cluster-server-ipv6", func(t *testing.T) {
		c := &Client{
			Clientset: fake.NewSimpleClientset(),
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"my-cluster": {
						Cluster: "my-cluster",
					},
				},
				Clusters: map[string]*clientcmdapi.Cluster{
					"my-cluster": {
						Server: "https://ABCDEF1234567890.gr7.eks-cluster.us-west-2.api.aws",
					},
				},
				CurrentContext: "my-cluster",
			},
			contextName: "my-cluster",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindEKS, flavor.Kind, "Should detect EKS via IPv6 cluster server URL")
	})
}

func TestIsTransientExecError(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		transient bool
	}{
		{
			name:      "nil",
			err:       nil,
			transient: false,
		},
		{
			name:      "spdy stream timed out under the exec session",
			err:       fmt.Errorf("command failed (pod=cilium-test-4/client-1, container=client): %w", spdystream.ErrTimeout),
			transient: true,
		},
		{
			name:      "spdy stream reset under the exec session",
			err:       fmt.Errorf("command failed (pod=cilium-test-4/client-1, container=client): %w", spdystream.ErrReset),
			transient: true,
		},
		{
			name:      "spdy stream closed under the exec session",
			err:       fmt.Errorf("command failed (pod=cilium-test-4/client-1, container=client): %w", spdystream.ErrWriteClosedStream),
			transient: true,
		},
		{
			name:      "apiserver unreachable",
			err:       errors.New("dial tcp 10.0.0.1:443: i/o timeout"),
			transient: true,
		},
		{
			name:      "command exited non-zero",
			err:       errors.New("command failed (pod=cilium-test-4/client-1, container=client): command terminated with exit code 1"),
			transient: false,
		},
		{
			name:      "command echoed a transport error to stderr",
			err:       errors.New(`command failed (pod=cilium-test-4/client-1, container=client): "Stream reset"`),
			transient: false,
		},
		{
			name:      "command wrote to stderr",
			err:       errors.New(`command failed (pod=kube-system/cilium-1, container=cilium-agent): "level=debug msg=probe failed"`),
			transient: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.transient, IsTransientExecError(tc.err))
		})
	}
}

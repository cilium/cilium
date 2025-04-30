// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"go.uber.org/goleak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authIdentity "github.com/cilium/cilium/operator/auth/identity"
	"github.com/cilium/cilium/operator/auth/spire"
	"github.com/cilium/cilium/operator/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

func TestIdentitiesGC(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		// To ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go
		// init function
		goleak.IgnoreTopFunction("time.Sleep"),
	)

	var clientset k8sClient.Clientset
	var authIdentityClient authIdentity.Provider

	hive := hive.New(
		cell.Config(cmtypes.DefaultClusterInfo),
		metrics.Metric(NewMetrics),

		// provide a fake clientset
		k8sClient.FakeClientCell,
		// provide a fake spire client
		spire.FakeCellClient,
		// provide resources
		k8s.ResourcesCell,

		// provide identities gc test configuration
		cell.Provide(func() Config {
			return Config{
				Interval:         50 * time.Millisecond,
				HeartbeatTimeout: 50 * time.Millisecond,

				RateInterval: time.Minute,
				RateLimit:    2500,
			}
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				IdentityAllocationMode: option.IdentityAllocationModeCRD,
			}
		}),

		// initial setup for the test
		cell.Invoke(func(c k8sClient.Clientset, authClient authIdentity.Provider) error {
			clientset = c
			authIdentityClient = authClient
			if err := setupK8sNodes(t, clientset); err != nil {
				return err
			}
			if err := setupCiliumIdentities(t, clientset); err != nil {
				return err
			}
			if err := setupCiliumEndpoint(t, clientset); err != nil {
				return err
			}
			if err := setupAuthIdentities(t, authIdentityClient); err != nil {
				return err
			}

			return nil
		}),

		cell.Invoke(registerGC),
	)

	ctx := t.Context()

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	var (
		identities *v2.CiliumIdentityList
		err        error
	)
	for range 10 {
		identities, err = clientset.CiliumV2().CiliumIdentities().List(
			ctx,
			metav1.ListOptions{
				LabelSelector: metav1.FormatLabelSelector(
					&metav1.LabelSelector{
						MatchLabels: map[string]string{
							"test": "identities-gc",
						},
					},
				),
			},
		)
		if err == nil && len(identities.Items) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("unable to list Cilium identities: %s", err)
	}
	if len(identities.Items) != 1 {
		t.Fatalf("expected 1 Cilium identity, got %d", len(identities.Items))
	}
	if identities.Items[0].Name != "99999" {
		t.Fatalf("expected Cilium identity \"99999\", got %q", identities.Items[0].Name)
	}

	authIdentities, err := authIdentityClient.List(ctx)
	if err != nil {
		t.Fatalf("unable to list Cilium Auth identities: %s", err)
	}

	if len(authIdentities) != 1 {
		t.Fatalf("expected 1 Cilium Auth identity, got %d", len(authIdentities))
	}

	if authIdentities[0] != "99999" {
		t.Fatalf("expected Cilium Auth identity \"99999\", got %q", authIdentities[0])
	}

	if err := hive.Stop(tlog, ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func setupK8sNodes(t *testing.T, clientset k8sClient.Clientset) error {
	nodes := []*corev1.Node{
		{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Node",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-control-plane",
				Labels: map[string]string{"kubernetes.io/hostname": "node-control-plane"},
			},
		},
		{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Node",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-worker",
				Labels: map[string]string{"kubernetes.io/hostname": "node-worker"},
			},
		},
	}
	for _, node := range nodes {
		if _, err := clientset.CoreV1().Nodes().
			Create(t.Context(), node, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create node %v: %w", node, err)
		}
	}
	return nil
}

func setupCiliumIdentities(t *testing.T, clientset k8sClient.Clientset) error {
	identities := []*v2.CiliumIdentity{
		{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2",
				Kind:       "CiliumIdentity",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "88888",
				Labels: map[string]string{
					"test": "identities-gc",
				},
			},
		},
		{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2",
				Kind:       "CiliumIdentity",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "99999",
				Labels: map[string]string{
					"test": "identities-gc",
				},
			},
		},
	}
	for _, identity := range identities {
		if _, err := clientset.CiliumV2().CiliumIdentities().
			Create(t.Context(), identity, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create identity %v: %w", identity, err)
		}
	}
	return nil
}

func setupAuthIdentities(t *testing.T, client authIdentity.Provider) error {
	if err := client.Upsert(t.Context(), "88888"); err != nil {
		return err
	}
	if err := client.Upsert(t.Context(), "99999"); err != nil {
		return err
	}
	return nil
}

func setupCiliumEndpoint(t *testing.T, clientset k8sClient.Clientset) error {
	endpoint := &v2.CiliumEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-endpoint",
		},
		Status: v2.EndpointStatus{
			Identity: &v2.EndpointIdentity{
				ID: 99999,
			},
		},
	}
	if _, err := clientset.CiliumV2().CiliumEndpoints("").
		Create(t.Context(), endpoint, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed to create endpoint %v: %w", endpoint, err)
	}
	return nil
}

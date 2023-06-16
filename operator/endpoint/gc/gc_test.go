// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/goleak"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

func TestGC(t *testing.T) {
	defer goleak.VerifyNone(t)

	var clientset k8sClient.Clientset

	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,

		job.Cell,
		cell.Provide(newMetrics),

		cell.Provide(func() Config {
			return Config{
				// one shot cep gc
				CiliumEndpointGCInterval: 0,
			}
		}),

		cell.Invoke(func(c k8sClient.Clientset) error {
			clientset = c
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
				Create(context.Background(), endpoint, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("failed to create cilium endpoint %v: %w", endpoint, err)
			}
			return nil
		}),

		cell.Invoke(registerGC),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	var (
		endpoint *v2.CiliumEndpoint
		err      error
	)
	for {
		endpoint, err = clientset.CiliumV2().CiliumEndpoints("").Get(
			ctx, "test-endpoint", metav1.GetOptions{},
		)
		if k8serrors.IsNotFound(err) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil && !k8serrors.IsNotFound(err) {
		t.Fatalf("CiliumEndpoint Get failed with unexpected error: %s", err)
	}
	if err == nil {
		t.Fatalf("unexptected CiliumEndpoint found after gc run: %v", endpoint)
	}

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

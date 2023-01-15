// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(
		m,
		// To ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go
		// init function
		goleak.IgnoreTopFunction("time.Sleep"),
		// To ignore leaked goroutine started from the instantiation
		// of global variable watchers.nodeQueue
		goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*delayingType).waitingLoop"),
	)
}

func TestIdentitiesGC(t *testing.T) {
	var clientset k8sClient.Clientset

	hive := hive.New(
		// provide a fake clientset
		k8sClient.FakeClientCell,

		// provide resources
		k8s.SharedResourcesCell,

		// provide identities gc test configuration
		cell.Provide(func() GCConfig {
			return GCConfig{
				GCInterval:       50 * time.Millisecond,
				HeartbeatTimeout: 50 * time.Millisecond,

				GCRateInterval: time.Minute,
				GCRateLimit:    2500,
			}
		}),
		cell.Provide(func() GCSharedConfig {
			return GCSharedConfig{
				IdentityAllocationMode: option.IdentityAllocationModeCRD,
				EnableMetrics:          false,
				ClusterName:            defaults.ClusterName,
				K8sNamespace:           "",
				ClusterID:              0,
			}
		}),

		// initial setup for the test
		cell.Invoke(func(c k8sClient.Clientset) error {
			clientset = c
			if err := setupK8sNodes(clientset); err != nil {
				return err
			}
			if err := setupCiliumIdentities(clientset); err != nil {
				return err
			}
			if err := setupCiliumEndpoint(clientset); err != nil {
				return err
			}
			return nil
		}),
		cell.Invoke(setupCiliumEndpointWatcher),
		cell.Invoke(newGC),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	var (
		identities *v2.CiliumIdentityList
		err        error
	)
	for retry := 0; retry < 10; retry++ {
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

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func setupK8sNodes(clientset k8sClient.Clientset) error {
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
			Create(context.Background(), node, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create node %v: %w", node, err)
		}
	}
	return nil
}

func setupCiliumIdentities(clientset k8sClient.Clientset) error {
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
			Create(context.Background(), identity, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create identity %v: %w", identity, err)
		}
	}
	return nil
}

func setupCiliumEndpoint(clientset k8sClient.Clientset) error {
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
		return fmt.Errorf("failed to create endpoint %v: %w", endpoint, err)
	}
	return nil
}

func setupCiliumEndpointWatcher(
	lc hive.Lifecycle,
	params gcParams,
) {
	var wg sync.WaitGroup

	lc.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			// identity gc internally depends on the global watchers.CiliumEndpointStore,
			// so we have to create a mock one here (and run an informer) to get the gc
			// to work properly.

			watchers.CiliumEndpointStore = cache.NewIndexer(
				cache.DeletionHandlingMetaNamespaceKeyFunc,
				cache.Indexers{
					cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
					"identity": func(obj interface{}) ([]string, error) {
						endpointObj, ok := obj.(*v2.CiliumEndpoint)
						if !ok {
							return nil, errors.New("failed to convert cilium endpoint")
						}
						identityID := "0"
						if endpointObj.Status.Identity != nil {
							identityID = strconv.FormatInt(endpointObj.Status.Identity.ID, 10)
						}
						return []string{identityID}, nil
					},
				},
			)
			ciliumEndpointInformer := informer.NewInformerWithStore(
				utils.ListerWatcherFromTyped[*v2.CiliumEndpointList](params.Clientset.CiliumV2().CiliumEndpoints("")),
				&v2.CiliumEndpoint{},
				0,
				cache.ResourceEventHandlerFuncs{},
				func(obj interface{}) interface{} {
					endpointObj, ok := obj.(*v2.CiliumEndpoint)
					if !ok {
						return errors.New("failed to convert cilium endpoint")
					}
					return &v2.CiliumEndpoint{
						TypeMeta: endpointObj.TypeMeta,
						ObjectMeta: metav1.ObjectMeta{
							Name: endpointObj.Name,
						},
						Status: v2.EndpointStatus{
							Identity: endpointObj.Status.Identity,
						},
					}
				},
				watchers.CiliumEndpointStore,
			)

			wg.Add(1)
			go func() {
				defer wg.Done()
				ciliumEndpointInformer.Run(ctx.Done())
			}()
			cache.WaitForCacheSync(ctx.Done(), ciliumEndpointInformer.HasSynced)
			// signal that endpoints are sync-ed, otherwise identities gc won't start
			close(watchers.CiliumEndpointsSynced)

			return nil
		},
		OnStop: func(ctx hive.HookContext) error {
			// wait for CiliumEndpointInformer goroutine to be cleaned up
			wg.Wait()

			return nil
		},
	})
}

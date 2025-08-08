// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sClientTestUtils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/statedb"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
)

func newService(namespace, name string) *slim_corev1.Service {
	return &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "1.2.3.4",
			Ports: []slim_corev1.ServicePort{
				{
					Port: 80,
				},
			},
		},
	}
}

func newEndpointSlice(namespace, name, serviceName string, endpoint string) *slim_discovery_v1.EndpointSlice {
	port := int32(80)
	return &slim_discovery_v1.EndpointSlice{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"kubernetes.io/service-name": serviceName,
			},
		},
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Port: &port,
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{endpoint},
			},
		},
	}
}
func TestK8sReflector(t *testing.T) {
	var (
		db        *statedb.DB
		w         *writer.Writer
		clientset k8sClient.Clientset
	)

	h := hive.New(
		cell.Module(
			"test-k8s-reflector",
			"Test K8s Reflector",

			// Provide fake k8s client and the tables for services, endpoints and pods.
			k8sClientTestUtils.FakeClientCell(),
			daemonk8s.SvcEPTablesCell,
			daemonk8s.PodTableCell,
			cell.Provide(
				statedb.RWTable[*slim_corev1.Service].ToTable,
				statedb.RWTable[*k8s.Endpoints].ToTable,
				statedb.RWTable[daemonk8s.LocalPod].ToTable,
			),

			// The reflector cell to test
			Cell,

			// And its dependencies
			writer.Cell,
			node.LocalNodeStoreCell,
			cell.Provide(
				func() loadbalancer.Config { return loadbalancer.Config{} },
				func() loadbalancer.ExternalConfig { return loadbalancer.ExternalConfig{EnableIPv4: true} },
				func() *option.DaemonConfig { return &option.DaemonConfig{} },
				lbmaps.NetnsCookieSupportFunc,

				// Dependencies for writer.Cell
				tables.NewNodeAddressTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
				source.NewSources,
			),
			cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),

			// Capture the created objects for the test to use
			cell.Invoke(func(
				db_ *statedb.DB,
				w_ *writer.Writer,
				cs k8sClient.Clientset,
			) {
				db = db_
				w = w_
				clientset = cs
			}),
		),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log := hivetest.Logger(t)
	err := h.Start(log, ctx)
	require.NoError(t, err, "starting hive")

	// Create a service and an endpoint slice
	svc := newService("default", "test-svc")
	_, err = clientset.Slim().CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{})
	require.NoError(t, err)

	epSlice := newEndpointSlice("default", "test-svc-1", svc.Name, "10.0.0.1")
	_, err = clientset.Slim().DiscoveryV1().EndpointSlices("default").Create(ctx, epSlice, metav1.CreateOptions{})
	require.NoError(t, err)

	// Wait for the reflector to process the objects and populate the LB tables.
	require.Eventually(t, func() bool {
		txn := db.ReadTxn()
		return w.Backends().NumObjects(txn) > 0
	}, 5*time.Second, 10*time.Millisecond, "backends not found")

	// Check that the backend has been created correctly.
	txn := db.ReadTxn()
	iter := w.Backends().All(txn)
	var be *loadbalancer.Backend
	for b := range iter {
		be = b
		break
	}
	require.NotNil(t, be, "expected a backend")
	require.Equal(t, "10.0.0.1", be.Address.AddrCluster().String())

	err = h.Stop(log, ctx)
	require.NoError(t, err, "stopping hive")
}

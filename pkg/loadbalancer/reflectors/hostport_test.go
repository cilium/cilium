// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

type hostPortTestParams struct {
	cell.In

	DB     *statedb.DB
	Writer *writer.Writer
}

func hostPortFixture(t testing.TB) (p hostPortTestParams) {
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))

	h := hive.New(
		loadbalancer.ConfigCell,
		node.LocalNodeStoreTestCell,
		writer.Cell,
		cell.Provide(
			func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
			func() *option.DaemonConfig { return &option.DaemonConfig{} },
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			source.NewSources,
			func() kpr.KPRConfig { return kpr.KPRConfig{} },
		),
		cell.Invoke(func(p_ hostPortTestParams) { p = p_ }),
	)

	require.NoError(t, h.Start(log, context.TODO()))
	t.Cleanup(func() { h.Stop(log, context.TODO()) })
	return p
}

func hostPortPod(uid string) *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "default",
			UID:       types.UID(uid),
		},
		Spec: slim_corev1.PodSpec{
			Containers: []slim_corev1.Container{{
				Name: "my-app",
				Ports: []slim_corev1.ContainerPort{{
					ContainerPort: 80,
					HostPort:      4444,
					Protocol:      slim_corev1.ProtocolTCP,
				}},
			}},
		},
		Status: slim_corev1.PodStatus{
			Phase:  slim_corev1.PodRunning,
			PodIP:  "10.244.1.113",
			PodIPs: []slim_corev1.PodIP{{IP: "10.244.1.113"}},
			HostIP: "172.19.0.3",
		},
	}
}

// A pod recreated under the same name gets a new UID, and the UID is part of
// the synthesized HostPort service name. The replacement must take over the
// frontend the previous pod's service owned.
func TestUpsertHostPort_PodRecreatedWithSameName(t *testing.T) {
	p := hostPortFixture(t)
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	extConfig := loadbalancer.ExternalConfig{EnableIPv4: true, EnableIPv6: true, KubeProxyReplacement: true}
	netnsCookie := func() bool { return true }

	wtxn := p.Writer.WriteTxn()
	require.NoError(t, upsertHostPort(netnsCookie, loadbalancer.DefaultConfig, extConfig, log, wtxn, p.Writer, hostPortPod("11111111-2e9b-4c61-8454-ae81344876d8")))
	wtxn.Commit()

	wtxn = p.Writer.WriteTxn()
	err := upsertHostPort(netnsCookie, loadbalancer.DefaultConfig, extConfig, log, wtxn, p.Writer, hostPortPod("22222222-2e9b-4c61-8454-ae81344876d8"))
	wtxn.Commit()
	require.NoError(t, err, "the recreated pod must take over the HostPort")

	txn := p.DB.ReadTxn()
	var names []string
	for svc := range p.Writer.Services().All(txn) {
		names = append(names, svc.Name.String())
	}
	require.Len(t, names, 1, "the previous pod's service must be gone, got %v", names)
	require.Contains(t, names[0], "22222222", "the frontend must be owned by the new pod's service")
}

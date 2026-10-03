// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"context"
	"log/slog"
	"slices"
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

func hostPortPodPorts(name, uid string, hostPorts ...int32) *slim_corev1.Pod {
	pod := hostPortPod(uid)
	pod.Name = name
	pod.Spec.Containers[0].Ports = nil
	for i, hp := range hostPorts {
		pod.Spec.Containers[0].Ports = append(pod.Spec.Containers[0].Ports, slim_corev1.ContainerPort{
			ContainerPort: int32(80 + i),
			HostPort:      hp,
			Protocol:      slim_corev1.ProtocolTCP,
		})
	}
	return pod
}

func serviceNames(t *testing.T, p hostPortTestParams) []string {
	t.Helper()
	txn := p.DB.ReadTxn()
	var names []string
	for svc := range p.Writer.Services().All(txn) {
		names = append(names, svc.Name.String())
	}
	slices.Sort(names)
	return names
}

// A HostPort wanted by the pod may already be owned by a service that is not
// one of this pod's orphans. That is a genuine conflict: the reflector must
// report it without having changed anything, rather than pruning the pod's
// previous services and applying the ports it happened to process first.
func TestUpsertHostPort_ConflictWithLiveServiceLeavesStateUnchanged(t *testing.T) {
	p := hostPortFixture(t)
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	extConfig := loadbalancer.ExternalConfig{EnableIPv4: true, EnableIPv6: true, KubeProxyReplacement: true}
	netnsCookie := func() bool { return true }

	upsert := func(pod *slim_corev1.Pod) error {
		wtxn := p.Writer.WriteTxn()
		err := upsertHostPort(netnsCookie, loadbalancer.DefaultConfig, extConfig, log, wtxn, p.Writer, pod)
		wtxn.Commit()
		return err
	}

	// An unrelated pod holds host port 5555.
	require.NoError(t, upsert(hostPortPodPorts("other-app", "aaaaaaaa-0000-0000-0000-000000000001", 5555)))
	// my-app holds host port 4444.
	require.NoError(t, upsert(hostPortPodPorts("my-app", "11111111-0000-0000-0000-000000000001", 4444)))

	before := serviceNames(t, p)
	require.Len(t, before, 2)

	// my-app is recreated and now also asks for 5555, which other-app owns.
	err := upsert(hostPortPodPorts("my-app", "22222222-0000-0000-0000-000000000002", 4444, 5555))
	require.ErrorIs(t, err, loadbalancer.ErrFrontendConflict)

	require.Equal(t, before, serviceNames(t, p),
		"nothing may be pruned or inserted when a wanted frontend is owned by a live service")
}

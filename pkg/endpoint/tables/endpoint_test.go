// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimmeta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8stypes "github.com/cilium/cilium/pkg/k8s/types"
)

func TestWriterMergesCEPAndKVStoreByCEPName(t *testing.T) {
	db, table, writer := newFixture(t)

	cepSource, err := SourceFromCEP("cluster-a", newSlimCEP("default", "netcheck-eth1", "cep-uid", "10.0.0.10"))
	require.NoError(t, err)

	wtxn := db.WriteTxn(table)
	_, err = writer.Upsert(wtxn, cepSource)
	require.NoError(t, err)
	wtxn.Commit()

	kvSource, err := SourceFromIPIdentityPair("cluster-a", &identity.IPIdentityPair{
		IP:                net.ParseIP("10.0.0.10"),
		HostIP:            net.ParseIP("192.0.2.10"),
		ID:                1001,
		Key:               4,
		Metadata:          "cilium-global:cluster-a:node-a:123",
		K8sNamespace:      "default",
		K8sPodName:        "netcheck",
		K8sCEPName:        "netcheck-eth1",
		K8sServiceAccount: "default",
	})
	require.NoError(t, err)

	wtxn = db.WriteTxn(table)
	ep, err := writer.Upsert(wtxn, kvSource)
	require.NoError(t, err)
	wtxn.Commit()

	require.Equal(t, K8sEndpointKey("cluster-a", "default", "netcheck-eth1"), ep.Key)
	require.Len(t, ep.Sources, 2)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.10")}, ep.IPs)

	rows := collectEndpoints(db, table)
	require.Len(t, rows, 1)

	wtxn = db.WriteTxn(table)
	var found bool
	ep, found, err = writer.DeleteSource(wtxn, kvSource.Key)
	require.NoError(t, err)
	require.True(t, found)
	wtxn.Commit()

	require.NotNil(t, ep)
	require.Len(t, ep.Sources, 1)
	require.Contains(t, ep.Sources, cepSource.Key)
	require.Len(t, collectEndpoints(db, table), 1)
}

func TestWriterMergesDualStackKVStorePairsByGlobalEndpointID(t *testing.T) {
	db, table, writer := newFixture(t)
	v4 := newKVSource(t, "10.0.0.10", "", "", "cilium-global:cluster-a:node-a:123")
	v6 := newKVSource(t, "fd00::10", "", "", "cilium-global:cluster-a:node-a:123")

	wtxn := db.WriteTxn(table)
	_, err := writer.Upsert(wtxn, v4)
	require.NoError(t, err)
	ep, err := writer.Upsert(wtxn, v6)
	require.NoError(t, err)
	wtxn.Commit()

	require.Equal(t, GlobalEndpointKey("cluster-a", "node-a", "123"), ep.Key)
	require.Len(t, ep.Sources, 2)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("fd00::10")}, ep.IPs)
	require.Len(t, collectEndpoints(db, table), 1)
}

func TestWriterDoesNotGuessMergeByIPAndIdentity(t *testing.T) {
	db, table, writer := newFixture(t)

	cepSource, err := SourceFromCEP("cluster-a", newSlimCEP("default", "netcheck", "cep-uid", "10.0.0.10"))
	require.NoError(t, err)
	kvSource := newKVSource(t, "10.0.0.10", "", "", "cilium-global:cluster-a:node-a:123")

	wtxn := db.WriteTxn(table)
	_, err = writer.Upsert(wtxn, cepSource)
	require.NoError(t, err)
	_, err = writer.Upsert(wtxn, kvSource)
	require.NoError(t, err)
	wtxn.Commit()

	rows := collectEndpoints(db, table)
	require.Len(t, rows, 2)
	requireEndpointKeys(t, rows,
		K8sEndpointKey("cluster-a", "default", "netcheck"),
		GlobalEndpointKey("cluster-a", "node-a", "123"),
	)
}

func TestWriterUsesPodNameBridgeForLegacyKVStorePairs(t *testing.T) {
	db, table, writer := newFixture(t)

	cepSource, err := SourceFromCEP("cluster-a", newSlimCEP("default", "netcheck", "cep-uid", "10.0.0.10"))
	require.NoError(t, err)
	kvSource := newKVSource(t, "10.0.0.10", "default", "netcheck", "cilium-global:cluster-a:node-a:123")

	wtxn := db.WriteTxn(table)
	_, err = writer.Upsert(wtxn, cepSource)
	require.NoError(t, err)
	ep, err := writer.Upsert(wtxn, kvSource)
	require.NoError(t, err)
	wtxn.Commit()

	require.Equal(t, K8sEndpointKey("cluster-a", "default", "netcheck"), ep.Key)
	require.Len(t, ep.Sources, 2)
	require.Len(t, collectEndpoints(db, table), 1)
}

func TestSourcesFromCES(t *testing.T) {
	ces := &ciliumv2alpha1.CiliumEndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "ces-a"},
		Namespace:  "default",
		Endpoints: []ciliumv2alpha1.CoreCiliumEndpoint{{
			Name:       "netcheck",
			IdentityID: 1001,
			PodUID:     "pod-uid",
			Networking: &ciliumv2.EndpointNetworking{
				Addressing: ciliumv2.AddressPairList{{
					IPV4: "10.0.0.10",
					IPV6: "fd00::10",
				}},
				NodeIP: "192.0.2.10",
			},
			Encryption: ciliumv2.EncryptionSpec{Key: 4},
			NamedPorts: models.NamedPorts{{
				Name:     "http",
				Port:     8080,
				Protocol: "TCP",
			}},
			ServiceAccount: "default",
		}},
	}

	sources, err := SourcesFromCES("cluster-a", ces)
	require.NoError(t, err)
	require.Len(t, sources, 1)
	require.Equal(t, CESSourceKey("cluster-a", "ces-a", "default", "netcheck", "pod-uid"), sources[0].Key)
	require.Equal(t, K8sEndpointKey("cluster-a", "default", "netcheck"), sources[0].EndpointKey)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("fd00::10")}, sources[0].IPs)
}

func TestEndpointResourceReflectorUpdatesCESMembership(t *testing.T) {
	db, table, writer := newFixture(t)
	reflector := endpointResourceReflector{
		db:          db,
		table:       table,
		writer:      writer,
		clusterName: "cluster-a",
		cesSources:  make(map[resource.Key][]SourceKey),
	}
	key := resource.Key{Name: "ces-a"}
	ces := newCES("ces-a", "default",
		newCoreCEP("netcheck-a", "pod-a", "10.0.0.10"),
		newCoreCEP("netcheck-b", "pod-b", "10.0.0.11"),
	)

	require.NoError(t, reflector.upsertCES(key, ces))
	requireEndpointKeys(t, collectEndpoints(db, table),
		K8sEndpointKey("cluster-a", "default", "netcheck-a"),
		K8sEndpointKey("cluster-a", "default", "netcheck-b"),
	)

	ces.Endpoints = ces.Endpoints[:1]
	require.NoError(t, reflector.upsertCES(key, ces))
	requireEndpointKeys(t, collectEndpoints(db, table),
		K8sEndpointKey("cluster-a", "default", "netcheck-a"),
	)

	require.NoError(t, reflector.deleteCES(key, ces))
	require.Empty(t, collectEndpoints(db, table))
}

func TestKVStoreIPIdentityReflectorMergesAndDeletesSource(t *testing.T) {
	db, table, writer := newFixture(t)
	cepSource, err := SourceFromCEP("cluster-a", newSlimCEP("default", "netcheck-eth1", "cep-uid", "10.0.0.10"))
	require.NoError(t, err)

	wtxn := db.WriteTxn(table)
	_, err = writer.Upsert(wtxn, cepSource)
	require.NoError(t, err)
	wtxn.Commit()

	reflector := kvstoreIPIdentityReflector{
		db:     db,
		table:  table,
		writer: writer,
	}
	pair := &identity.IPIdentityPair{
		IP:                net.ParseIP("10.0.0.10"),
		HostIP:            net.ParseIP("192.0.2.10"),
		ID:                1001,
		Key:               4,
		Metadata:          "cilium-global:cluster-a:node-a:123",
		K8sNamespace:      "default",
		K8sPodName:        "netcheck",
		K8sCEPName:        "netcheck-eth1",
		K8sServiceAccount: "default",
	}

	require.NoError(t, reflector.OnIPIdentityPairUpsert("cluster-a", pair))
	rows := collectEndpoints(db, table)
	require.Len(t, rows, 1)
	require.Equal(t, K8sEndpointKey("cluster-a", "default", "netcheck-eth1"), rows[0].Key)
	require.Len(t, rows[0].Sources, 2)

	require.NoError(t, reflector.OnIPIdentityPairDelete("cluster-a", pair))
	rows = collectEndpoints(db, table)
	require.Len(t, rows, 1)
	require.Contains(t, rows[0].Sources, cepSource.Key)
	require.NotContains(t, rows[0].Sources, KVStoreSourceKey("cluster-a", pair.PrefixString()))
}

func TestSourceFromIPIdentityPairRejectsPrefixes(t *testing.T) {
	_, err := SourceFromIPIdentityPair("cluster-a", &identity.IPIdentityPair{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(24, 32),
		ID:   1001,
	})
	require.Error(t, err)
}

func newFixture(t *testing.T) (*statedb.DB, statedb.RWTable[*Endpoint], *Writer) {
	t.Helper()
	db := statedb.New()
	table, err := NewEndpointTable(db)
	require.NoError(t, err)
	return db, table, NewWriter(table)
}

func newSlimCEP(namespace, name, uid, ip string) *k8stypes.CiliumEndpoint {
	return &k8stypes.CiliumEndpoint{
		ObjectMeta: slimmeta.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       k8sTypes.UID(uid),
		},
		Identity: &ciliumv2.EndpointIdentity{ID: 1001},
		Networking: &ciliumv2.EndpointNetworking{
			Addressing: ciliumv2.AddressPairList{{
				IPV4: ip,
			}},
			NodeIP: "192.0.2.10",
		},
		Encryption:     &ciliumv2.EncryptionSpec{Key: 4},
		ServiceAccount: "default",
	}
}

func newKVSource(t *testing.T, ip, namespace, podName, metadata string) Source {
	t.Helper()
	source, err := SourceFromIPIdentityPair("cluster-a", &identity.IPIdentityPair{
		IP:                net.ParseIP(ip),
		HostIP:            net.ParseIP("192.0.2.10"),
		ID:                1001,
		Key:               4,
		Metadata:          metadata,
		K8sNamespace:      namespace,
		K8sPodName:        podName,
		K8sServiceAccount: "default",
	})
	require.NoError(t, err)
	return source
}

func newCES(name, namespace string, endpoints ...ciliumv2alpha1.CoreCiliumEndpoint) *ciliumv2alpha1.CiliumEndpointSlice {
	return &ciliumv2alpha1.CiliumEndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Namespace:  namespace,
		Endpoints:  endpoints,
	}
}

func newCoreCEP(name, podUID, ip string) ciliumv2alpha1.CoreCiliumEndpoint {
	return ciliumv2alpha1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: 1001,
		PodUID:     podUID,
		Networking: &ciliumv2.EndpointNetworking{
			Addressing: ciliumv2.AddressPairList{{
				IPV4: ip,
			}},
			NodeIP: "192.0.2.10",
		},
		Encryption:     ciliumv2.EncryptionSpec{Key: 4},
		ServiceAccount: "default",
	}
}

func collectEndpoints(db *statedb.DB, table statedb.Table[*Endpoint]) []*Endpoint {
	var endpoints []*Endpoint
	for ep := range table.All(db.ReadTxn()) {
		endpoints = append(endpoints, ep)
	}
	return endpoints
}

func requireEndpointKeys(t *testing.T, endpoints []*Endpoint, keys ...EndpointKey) {
	t.Helper()
	have := make([]EndpointKey, 0, len(endpoints))
	for _, ep := range endpoints {
		have = append(have, ep.Key)
	}
	require.ElementsMatch(t, keys, have)
}

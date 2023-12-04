// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"unsafe"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// Identities also have scopes, which is defined by the high 8 bits.
	// 0x00 -- Global and reserved identities. Reserved identities are
	//         not allocated like global identities, but are known
	//         because they are hardcoded in Cilium. Older versions of
	//         Cilium will not be aware of any "new" reserved identities
	//         that are added.
	// 0x01 -- local (CIDR) identities
	// 0x02 -- remote nodes

	// IdentityScopeMask is the top 8 bits of the 32 bit identity
	IdentityScopeMask = NumericIdentity(0xFF_00_00_00)

	// IdentityScopeGlobal is the identity scope used by global and reserved identities.
	IdentityScopeGlobal = NumericIdentity(0)

	// IdentityScopeLocal is the tag in the numeric identity that identifies
	// a numeric identity to have local (CIDR) scope.
	IdentityScopeLocal = NumericIdentity(1 << 24)

	// IdentityScopeRemoteNode is the tag in the numeric identity that identifies
	// an identity to be a remote in-cluster node.
	IdentityScopeRemoteNode = NumericIdentity(2 << 24)

	// MinAllocatorLocalIdentity represents the minimal numeric identity
	// that the localIdentityCache allocator can allocate for a local (CIDR)
	// identity.
	//
	// Note that this does not represents the minimal value for a local
	// identity, as the allocated ID will then be bitwise OR'ed with
	// LocalIdentityFlag.
	MinAllocatorLocalIdentity = 1

	// MinLocalIdentity represents the actual minimal numeric identity value
	// for a local (CIDR) identity.
	MinLocalIdentity = MinAllocatorLocalIdentity | IdentityScopeLocal

	// MaxAllocatorLocalIdentity represents the maximal numeric identity
	// that the localIdentityCache allocator can allocate for a local (CIDR)
	// identity.
	//
	// Note that this does not represents the maximal value for a local
	// identity, as the allocated ID will then be bitwise OR'ed with
	// LocalIdentityFlag.
	MaxAllocatorLocalIdentity = 0xFFFFFF

	// MaxLocalIdentity represents the actual maximal numeric identity value
	// for a local (CIDR) identity.
	MaxLocalIdentity = MaxAllocatorLocalIdentity | IdentityScopeLocal

	// MinimalNumericIdentity represents the minimal numeric identity not
	// used for reserved purposes.
	MinimalNumericIdentity = NumericIdentity(256)

	// UserReservedNumericIdentity represents the minimal numeric identity that
	// can be used by users for reserved purposes.
	UserReservedNumericIdentity = NumericIdentity(128)

	// InvalidIdentity is the identity assigned if the identity is invalid
	// or not determined yet
	InvalidIdentity = NumericIdentity(0)
)

var (
	// clusterIDInit ensures that clusterIDLen and clusterIDShift can only be
	// set once, and only if we haven't used either value elsewhere already.
	clusterIDInit sync.Once

	// clusterIDShift is the number of bits to shift a cluster ID in a numeric
	// identity and is equal to the number of bits that represent a cluster-local identity.
	clusterIDShift uint32
)

const (
	// IdentityUnknown represents an unknown identity
	IdentityUnknown NumericIdentity = iota

	// ReservedIdentityHost represents the local host
	ReservedIdentityHost

	// ReservedIdentityWorld represents any endpoint outside of the cluster
	ReservedIdentityWorld

	// ReservedIdentityUnmanaged represents unmanaged endpoints.
	ReservedIdentityUnmanaged

	// ReservedIdentityHealth represents the local cilium-health endpoint
	ReservedIdentityHealth

	// ReservedIdentityInit is the identity given to endpoints that have not
	// received any labels yet.
	ReservedIdentityInit

	// ReservedIdentityRemoteNode is the identity given to all nodes in
	// local and remote clusters except for the local node.
	ReservedIdentityRemoteNode

	// ReservedIdentityKubeAPIServer is the identity given to remote node(s) which
	// have backend(s) serving the kube-apiserver running.
	ReservedIdentityKubeAPIServer

	// ReservedIdentityIngress is the identity given to the IP used as the source
	// address for connections from Ingress proxies.
	ReservedIdentityIngress

	// ReservedIdentityWorldIPv4 represents any endpoint outside of the cluster
	// for IPv4 address only.
	ReservedIdentityWorldIPv4

	// ReservedIdentityWorldIPv6 represents any endpoint outside of the cluster
	// for IPv6 address only.
	ReservedIdentityWorldIPv6
)

// Special identities for well-known cluster components
// Each component has two identities. The first one is used for Kubernetes <1.21
// or when the NamespaceDefaultLabelName feature gate is disabled. The second
// one is used for Kubernetes >= 1.21 and when the NamespaceDefaultLabelName is
// enabled.
const (
	// ReservedETCDOperator is the reserved identity used for the etcd-operator
	// managed by Cilium.
	ReservedETCDOperator NumericIdentity = iota + 100

	// ReservedCiliumKVStore is the reserved identity used for the kvstore
	// managed by Cilium (etcd-operator).
	ReservedCiliumKVStore

	// ReservedKubeDNS is the reserved identity used for kube-dns.
	ReservedKubeDNS

	// ReservedEKSKubeDNS is the reserved identity used for kube-dns on EKS
	ReservedEKSKubeDNS

	// ReservedCoreDNS is the reserved identity used for CoreDNS
	ReservedCoreDNS

	// ReservedCiliumOperator is the reserved identity used for the Cilium operator
	ReservedCiliumOperator

	// ReservedEKSCoreDNS is the reserved identity used for CoreDNS on EKS
	ReservedEKSCoreDNS

	// ReservedCiliumEtcdOperator is the reserved identity used for the Cilium etcd operator
	ReservedCiliumEtcdOperator

	// Second identities for all above components
	ReservedETCDOperator2
	ReservedCiliumKVStore2
	ReservedKubeDNS2
	ReservedEKSKubeDNS2
	ReservedCoreDNS2
	ReservedCiliumOperator2
	ReservedEKSCoreDNS2
	ReservedCiliumEtcdOperator2
)

// localNodeIdentity is the endpoint identity allocated for the local node
var localNodeIdentity = struct {
	lock.Mutex
	identity NumericIdentity
}{
	identity: ReservedIdentityRemoteNode,
}

type wellKnownIdentities map[NumericIdentity]wellKnownIdentity

// wellKnownIdentitity is an identity for well-known security labels for which
// a well-known numeric identity is reserved to avoid requiring a cluster wide
// setup. Examples of this include kube-dns and the etcd-operator.
type wellKnownIdentity struct {
	identity   *Identity
	labelArray labels.LabelArray
}

func (w wellKnownIdentities) add(i NumericIdentity, lbls []string) {
	labelMap := labels.NewLabelsFromModel(lbls)
	identity := NewIdentity(i, labelMap)
	w[i] = wellKnownIdentity{
		identity:   NewIdentity(i, labelMap),
		labelArray: labelMap.LabelArray(),
	}

	cacheMU.Lock()
	reservedIdentityCache[i] = identity
	cacheMU.Unlock()
}

func (w wellKnownIdentities) LookupByLabels(lbls labels.Labels) *Identity {
	for _, i := range w {
		if lbls.Equals(i.identity.Labels) {
			return i.identity
		}
	}

	return nil
}

func (w wellKnownIdentities) lookupByNumericIdentity(identity NumericIdentity) *Identity {
	wki, ok := w[identity]
	if !ok {
		return nil
	}
	return wki.identity
}

type Configuration interface {
	CiliumNamespaceName() string
}

func k8sLabel(key string, value string) string {
	return "k8s:" + key + "=" + value
}

// InitWellKnownIdentities establishes all well-known identities. Returns the
// number of well-known identities initialized.
func InitWellKnownIdentities(c Configuration, cinfo cmtypes.ClusterInfo) int {
	// etcd-operator labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-etcd-sa
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:io.cilium/app=etcd-operator
	//   k8s:io.cilium.k8s.policy.cluster=default
	etcdOperatorLabels := []string{
		"k8s:io.cilium/app=etcd-operator",
		k8sLabel(api.PodNamespaceLabel, c.CiliumNamespaceName()),
		k8sLabel(api.PolicyLabelServiceAccount, "cilium-etcd-sa"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	WellKnown.add(ReservedETCDOperator, etcdOperatorLabels)
	WellKnown.add(ReservedETCDOperator2, append(etcdOperatorLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, c.CiliumNamespaceName())))

	// cilium-etcd labels
	//   k8s:app=etcd
	//   k8s:io.cilium/app=etcd-operator
	//   k8s:etcd_cluster=cilium-etcd
	//   k8s:io.cilium.k8s.policy.serviceaccount=default
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:io.cilium.k8s.policy.cluster=default
	// these 2 labels are ignored by cilium-agent as they can change over time
	//   container:annotation.etcd.version=3.3.9
	//   k8s:etcd_node=cilium-etcd-6snk6vsjcm
	ciliumEtcdLabels := []string{
		"k8s:app=etcd",
		"k8s:etcd_cluster=cilium-etcd",
		"k8s:io.cilium/app=etcd-operator",
		k8sLabel(api.PodNamespaceLabel, c.CiliumNamespaceName()),
		k8sLabel(api.PolicyLabelServiceAccount, "default"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	WellKnown.add(ReservedCiliumKVStore, ciliumEtcdLabels)
	WellKnown.add(ReservedCiliumKVStore2, append(ciliumEtcdLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, c.CiliumNamespaceName())))

	// kube-dns labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=kube-dns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	kubeDNSLabels := []string{
		"k8s:k8s-app=kube-dns",
		k8sLabel(api.PodNamespaceLabel, "kube-system"),
		k8sLabel(api.PolicyLabelServiceAccount, "kube-dns"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	WellKnown.add(ReservedKubeDNS, kubeDNSLabels)
	WellKnown.add(ReservedKubeDNS2, append(kubeDNSLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, "kube-system")))

	// kube-dns EKS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=kube-dns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:eks.amazonaws.com/component=kube-dns
	eksKubeDNSLabels := []string{
		"k8s:k8s-app=kube-dns",
		"k8s:eks.amazonaws.com/component=kube-dns",
		k8sLabel(api.PodNamespaceLabel, "kube-system"),
		k8sLabel(api.PolicyLabelServiceAccount, "kube-dns"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	WellKnown.add(ReservedEKSKubeDNS, eksKubeDNSLabels)
	WellKnown.add(ReservedEKSKubeDNS2, append(eksKubeDNSLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, "kube-system")))

	// CoreDNS EKS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=coredns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:eks.amazonaws.com/component=coredns
	eksCoreDNSLabels := []string{
		"k8s:k8s-app=kube-dns",
		"k8s:eks.amazonaws.com/component=coredns",
		k8sLabel(api.PodNamespaceLabel, "kube-system"),
		k8sLabel(api.PolicyLabelServiceAccount, "coredns"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	WellKnown.add(ReservedEKSCoreDNS, eksCoreDNSLabels)
	WellKnown.add(ReservedEKSCoreDNS2, append(eksCoreDNSLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, "kube-system")))

	// CoreDNS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=coredns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	coreDNSLabels := []string{
		"k8s:k8s-app=kube-dns",
		k8sLabel(api.PodNamespaceLabel, "kube-system"),
		k8sLabel(api.PolicyLabelServiceAccount, "coredns"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	WellKnown.add(ReservedCoreDNS, coreDNSLabels)
	WellKnown.add(ReservedCoreDNS2, append(coreDNSLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, "kube-system")))

	// CiliumOperator labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-operator
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:name=cilium-operator
	//   k8s:io.cilium/app=operator
	//   k8s:app.kubernetes.io/part-of=cilium
	//   k8s:app.kubernetes.io/name=cilium-operator
	//   k8s:io.cilium.k8s.policy.cluster=default
	ciliumOperatorLabels := []string{
		"k8s:name=cilium-operator",
		"k8s:io.cilium/app=operator",
		"k8s:app.kubernetes.io/part-of=cilium",
		"k8s:app.kubernetes.io/name=cilium-operator",
		k8sLabel(api.PodNamespaceLabel, c.CiliumNamespaceName()),
		k8sLabel(api.PolicyLabelServiceAccount, "cilium-operator"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	WellKnown.add(ReservedCiliumOperator, ciliumOperatorLabels)
	WellKnown.add(ReservedCiliumOperator2, append(ciliumOperatorLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, c.CiliumNamespaceName())))

	// cilium-etcd-operator labels
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-etcd-operator
	//   k8s:io.cilium/app=etcd-operator
	//   k8s:app.kubernetes.io/name: cilium-etcd-operator
	//   k8s:app.kubernetes.io/part-of: cilium
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:name=cilium-etcd-operator
	ciliumEtcdOperatorLabels := []string{
		"k8s:name=cilium-etcd-operator",
		"k8s:io.cilium/app=etcd-operator",
		"k8s:app.kubernetes.io/name: cilium-etcd-operator",
		"k8s:app.kubernetes.io/part-of: cilium",
		k8sLabel(api.PodNamespaceLabel, c.CiliumNamespaceName()),
		k8sLabel(api.PolicyLabelServiceAccount, "cilium-etcd-operator"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	WellKnown.add(ReservedCiliumEtcdOperator, ciliumEtcdOperatorLabels)
	WellKnown.add(ReservedCiliumEtcdOperator2, append(ciliumEtcdOperatorLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, c.CiliumNamespaceName())))

	return len(WellKnown)
}

// GetClusterIDShift returns the number of bits to shift a cluster ID in a numeric
// identity and is equal to the number of bits that represent a cluster-local identity.
// A sync.Once is used to ensure we only initialize clusterIDShift once.
func GetClusterIDShift() uint32 {
	clusterIDInit.Do(initClusterIDShift)
	return clusterIDShift
}

// initClusterIDShift sets variables that control the bit allocation of cluster
// ID in a numeric identity.
func initClusterIDShift() {
	// ClusterIDLen is the number of bits that represent a cluster ID in a numeric identity
	clusterIDLen := uint32(math.Log2(float64(cmtypes.ClusterIDMax + 1)))
	// ClusterIDShift is the number of bits to shift a cluster ID in a numeric identity
	clusterIDShift = NumericIdentityBitlength - clusterIDLen
}

// GetMinimalNumericIdentity returns the minimal numeric identity not used for
// reserved purposes.
func GetMinimalAllocationIdentity() NumericIdentity {
	if option.Config.ClusterID > 0 {
		// For ClusterID > 0, the identity range just starts from cluster shift,
		// no well-known-identities need to be reserved from the range.
		return NumericIdentity((1 << GetClusterIDShift()) * option.Config.ClusterID)
	}
	return MinimalNumericIdentity
}

// GetMaximumAllocationIdentity returns the maximum numeric identity that
// should be handed out by the identity allocator.
func GetMaximumAllocationIdentity() NumericIdentity {
	return NumericIdentity((1<<GetClusterIDShift())*(option.Config.ClusterID+1) - 1)
}

var (
	reservedIdentities = map[string]NumericIdentity{
		labels.IDNameHost:          ReservedIdentityHost,
		labels.IDNameWorld:         ReservedIdentityWorld,
		labels.IDNameWorldIPv4:     ReservedIdentityWorldIPv4,
		labels.IDNameWorldIPv6:     ReservedIdentityWorldIPv6,
		labels.IDNameUnmanaged:     ReservedIdentityUnmanaged,
		labels.IDNameHealth:        ReservedIdentityHealth,
		labels.IDNameInit:          ReservedIdentityInit,
		labels.IDNameRemoteNode:    ReservedIdentityRemoteNode,
		labels.IDNameKubeAPIServer: ReservedIdentityKubeAPIServer,
		labels.IDNameIngress:       ReservedIdentityIngress,
	}
	reservedIdentityNames = map[NumericIdentity]string{
		IdentityUnknown:               "unknown",
		ReservedIdentityHost:          labels.IDNameHost,
		ReservedIdentityWorld:         labels.IDNameWorld,
		ReservedIdentityWorldIPv4:     labels.IDNameWorldIPv4,
		ReservedIdentityWorldIPv6:     labels.IDNameWorldIPv6,
		ReservedIdentityUnmanaged:     labels.IDNameUnmanaged,
		ReservedIdentityHealth:        labels.IDNameHealth,
		ReservedIdentityInit:          labels.IDNameInit,
		ReservedIdentityRemoteNode:    labels.IDNameRemoteNode,
		ReservedIdentityKubeAPIServer: labels.IDNameKubeAPIServer,
		ReservedIdentityIngress:       labels.IDNameIngress,
	}
	reservedIdentityLabels = map[NumericIdentity]labels.Labels{
		ReservedIdentityHost:       labels.LabelHost,
		ReservedIdentityWorld:      labels.LabelWorld,
		ReservedIdentityWorldIPv4:  labels.LabelWorldIPv4,
		ReservedIdentityWorldIPv6:  labels.LabelWorldIPv6,
		ReservedIdentityUnmanaged:  labels.NewLabelsFromModel([]string{"reserved:" + labels.IDNameUnmanaged}),
		ReservedIdentityHealth:     labels.LabelHealth,
		ReservedIdentityInit:       labels.NewLabelsFromModel([]string{"reserved:" + labels.IDNameInit}),
		ReservedIdentityRemoteNode: labels.LabelRemoteNode,
		ReservedIdentityKubeAPIServer: labels.Map2Labels(map[string]string{
			labels.LabelKubeAPIServer.String(): "",
			labels.LabelRemoteNode.String():    "",
		}, ""),
		ReservedIdentityIngress: labels.LabelIngress,
	}

	// WellKnown identities stores global state of all well-known identities.
	WellKnown = wellKnownIdentities{}

	// ErrNotUserIdentity is an error returned for an identity that is not user
	// reserved.
	ErrNotUserIdentity = errors.New("not a user reserved identity")
)

// IsUserReservedIdentity returns true if the given NumericIdentity belongs
// to the space reserved for users.
func IsUserReservedIdentity(id NumericIdentity) bool {
	return id.Uint32() >= UserReservedNumericIdentity.Uint32() &&
		id.Uint32() < MinimalNumericIdentity.Uint32()
}

// AddUserDefinedNumericIdentity adds the given numeric identity and respective
// label to the list of reservedIdentities. If the numeric identity is not
// between UserReservedNumericIdentity and MinimalNumericIdentity it will return
// ErrNotUserIdentity.
// Is not safe for concurrent use.
func AddUserDefinedNumericIdentity(identity NumericIdentity, label string) error {
	if !IsUserReservedIdentity(identity) {
		return ErrNotUserIdentity
	}
	reservedIdentities[label] = identity
	reservedIdentityNames[identity] = label
	return nil
}

// DelReservedNumericIdentity deletes the given Numeric Identity from the list
// of reservedIdentities. If the numeric identity is not between
// UserReservedNumericIdentity and MinimalNumericIdentity it will return
// ErrNotUserIdentity.
// Is not safe for concurrent use.
func DelReservedNumericIdentity(identity NumericIdentity) error {
	if !IsUserReservedIdentity(identity) {
		return ErrNotUserIdentity
	}
	label, ok := reservedIdentityNames[identity]
	if ok {
		delete(reservedIdentities, label)
		delete(reservedIdentityNames, identity)
	}
	return nil
}

// NumericIdentity is the numeric representation of a security identity.
//
// Bits:
//
//	 0-15: identity identifier
//	16-23: cluster identifier
//	   24: LocalIdentityFlag: Indicates that the identity has a local scope
type NumericIdentity uint32

// NumericIdentityBitlength is the number of bits used on the wire for a
// NumericIdentity
const NumericIdentityBitlength = 24

// MaxNumericIdentity is the maximum value of a NumericIdentity.
const MaxNumericIdentity = math.MaxUint32

type NumericIdentitySlice []NumericIdentity

// AsUint32Slice returns the NumericIdentitySlice as a slice of uint32 without copying any data.
// This is safe as long as the underlying type stays as uint32.
func (nids NumericIdentitySlice) AsUint32Slice() []uint32 {
	if len(nids) == 0 {
		return nil
	}
	return unsafe.Slice((*uint32)(&nids[0]), len(nids))
}

func ParseNumericIdentity(id string) (NumericIdentity, error) {
	nid, err := strconv.ParseUint(id, 0, 32)
	if err != nil {
		return NumericIdentity(0), err
	}
	if nid > MaxNumericIdentity {
		return NumericIdentity(0), fmt.Errorf("%s: numeric identity too large", id)
	}
	return NumericIdentity(nid), nil
}

func (id NumericIdentity) StringID() string {
	return strconv.FormatUint(uint64(id), 10)
}

func (id NumericIdentity) String() string {
	if v, exists := reservedIdentityNames[id]; exists {
		return v
	}

	return id.StringID()
}

// Uint32 normalizes the ID for use in BPF program.
func (id NumericIdentity) Uint32() uint32 {
	return uint32(id)
}

// GetLocalNodeID returns the configured local node numeric identity that is
// set in tunnel headers when encapsulating packets originating from the local
// node.
func GetLocalNodeID() NumericIdentity {
	localNodeIdentity.Lock()
	defer localNodeIdentity.Unlock()
	return localNodeIdentity.identity
}

// SetLocalNodeID sets the local node id.
// Note that currently changes to the local node id only take effect during agent bootstrap
func SetLocalNodeID(nodeid uint32) {
	localNodeIdentity.Lock()
	defer localNodeIdentity.Unlock()
	localNodeIdentity.identity = NumericIdentity(nodeid)
}

func GetReservedID(name string) NumericIdentity {
	if v, ok := reservedIdentities[name]; ok {
		return v
	}
	return IdentityUnknown
}

// IsReservedIdentity returns whether id is one of the special reserved identities.
func (id NumericIdentity) IsReservedIdentity() bool {
	_, isReservedIdentity := reservedIdentityNames[id]
	return isReservedIdentity
}

// ClusterID returns the cluster ID associated with the identity
func (id NumericIdentity) ClusterID() uint32 {
	return (uint32(id) >> uint32(GetClusterIDShift())) & cmtypes.ClusterIDMax
}

// GetAllReservedIdentities returns a list of all reserved numeric identities
// in ascending order.
// NOTE: While this func is unused from the cilium repository, is it imported
// and called by the hubble cli.
func GetAllReservedIdentities() []NumericIdentity {
	identities := make([]NumericIdentity, 0, len(reservedIdentities))
	for _, id := range reservedIdentities {
		identities = append(identities, id)
	}
	// Because our reservedIdentities source is a go map, and go map order is
	// randomized, we need to sort the resulting slice before returning it.
	sort.Slice(identities, func(i, j int) bool {
		return identities[i].Uint32() < identities[j].Uint32()
	})
	return identities
}

// GetWorldIdentityFromIP gets the correct world identity based
// on the IP address version. If Cilium is not in dual-stack mode
// then ReservedIdentityWorld will always be returned.
func GetWorldIdentityFromIP(addr netip.Addr) NumericIdentity {
	if option.Config.IsDualStack() {
		if addr.Is6() {
			return ReservedIdentityWorldIPv6
		}
		return ReservedIdentityWorldIPv4
	}
	return ReservedIdentityWorld
}

// iterateReservedIdentityLabels iterates over all reservedIdentityLabels and
// executes the given function for each key, value pair in
// reservedIdentityLabels.
func iterateReservedIdentityLabels(f func(_ NumericIdentity, _ labels.Labels)) {
	for ni, lbls := range reservedIdentityLabels {
		f(ni, lbls)
	}
}

// HasLocalScope returns true if the identity is in the Local (CIDR) scope
func (id NumericIdentity) HasLocalScope() bool {
	return id.Scope() == IdentityScopeLocal
}

func (id NumericIdentity) HasRemoteNodeScope() bool {
	return id.Scope() == IdentityScopeRemoteNode
}

// Scope returns the identity scope of this given numeric ID.
func (id NumericIdentity) Scope() NumericIdentity {
	return id & IdentityScopeMask
}

// IsWorld returns true if the identity is one of the world identities
func (id NumericIdentity) IsWorld() bool {
	if id == ReservedIdentityWorld {
		return true
	}
	return option.Config.IsDualStack() &&
		(id == ReservedIdentityWorldIPv4 || id == ReservedIdentityWorldIPv6)
}

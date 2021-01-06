// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identity

import (
	"errors"
	"fmt"
	"strconv"

	api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	// ClusterIDShift specifies the number of bits the cluster ID will be
	// shifted
	ClusterIDShift = 16

	// LocalIdentityFlag is the bit in the numeric identity that identifies
	// a numeric identity to have local scope
	LocalIdentityFlag = NumericIdentity(1 << 24)

	// MinimalNumericIdentity represents the minimal numeric identity not
	// used for reserved purposes.
	MinimalNumericIdentity = NumericIdentity(256)

	// MinimalAllocationIdentity is the minimum numeric identity handed out
	// by the identity allocator.
	MinimalAllocationIdentity = MinimalNumericIdentity

	// MaximumAllocationIdentity is the maximum numeric identity handed out
	// by the identity allocator
	MaximumAllocationIdentity = NumericIdentity(^uint16(0))

	// UserReservedNumericIdentity represents the minimal numeric identity that
	// can be used by users for reserved purposes.
	UserReservedNumericIdentity = NumericIdentity(128)

	// InvalidIdentity is the identity assigned if the identity is invalid
	// or not determined yet
	InvalidIdentity = NumericIdentity(0)
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

	// --------------------------------------------------------------
	// Special identities for well-known cluster components

	// ReservedETCDOperator is the reserved identity used for the etcd-operator
	// managed by Cilium.
	ReservedETCDOperator NumericIdentity = 100

	// ReservedCiliumKVStore is the reserved identity used for the kvstore
	// managed by Cilium (etcd-operator).
	ReservedCiliumKVStore NumericIdentity = 101

	// ReservedKubeDNS is the reserved identity used for kube-dns.
	ReservedKubeDNS NumericIdentity = 102

	// ReservedEKSKubeDNS is the reserved identity used for kube-dns on EKS
	ReservedEKSKubeDNS NumericIdentity = 103

	// ReservedCoreDNS is the reserved identity used for CoreDNS
	ReservedCoreDNS NumericIdentity = 104

	// ReservedCiliumOperator is the reserved identity used for the Cilium operator
	ReservedCiliumOperator NumericIdentity = 105

	// ReservedEKSCoreDNS is the reserved identity used for CoreDNS on EKS
	ReservedEKSCoreDNS NumericIdentity = 106

	// ReservedCiliumEtcdOperator is the reserved identity used for the Cilium etcd operator
	ReservedCiliumEtcdOperator NumericIdentity = 107
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

	ReservedIdentityCache[i] = identity
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
	LocalClusterName() string
	CiliumNamespaceName() string
}

// InitWellKnownIdentities establishes all well-known identities. Returns the
// number of well-known identities initialized.
func InitWellKnownIdentities(c Configuration) int {
	// etcd-operator labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-etcd-sa
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:io.cilium/app=etcd-operator
	//   k8s:io.cilium.k8s.policy.cluster=default
	WellKnown.add(ReservedETCDOperator, []string{
		"k8s:io.cilium/app=etcd-operator",
		fmt.Sprintf("k8s:%s=%s", api.PodNamespaceLabel, c.CiliumNamespaceName()),
		fmt.Sprintf("k8s:%s=cilium-etcd-sa", api.PolicyLabelServiceAccount),
		fmt.Sprintf("k8s:%s=%s", api.PolicyLabelCluster, c.LocalClusterName()),
	})

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
	WellKnown.add(ReservedCiliumKVStore, []string{
		"k8s:app=etcd",
		"k8s:etcd_cluster=cilium-etcd",
		"k8s:io.cilium/app=etcd-operator",
		fmt.Sprintf("k8s:%s=%s", api.PodNamespaceLabel, c.CiliumNamespaceName()),
		fmt.Sprintf("k8s:%s=default", api.PolicyLabelServiceAccount),
		fmt.Sprintf("k8s:%s=%s", api.PolicyLabelCluster, c.LocalClusterName()),
	})

	// kube-dns labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=kube-dns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	WellKnown.add(ReservedKubeDNS, []string{
		"k8s:k8s-app=kube-dns",
		fmt.Sprintf("k8s:%s=kube-system", api.PodNamespaceLabel),
		fmt.Sprintf("k8s:%s=kube-dns", api.PolicyLabelServiceAccount),
		fmt.Sprintf("k8s:%s=%s", api.PolicyLabelCluster, c.LocalClusterName()),
	})

	// kube-dns EKS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=kube-dns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:eks.amazonaws.com/component=kube-dns
	WellKnown.add(ReservedEKSKubeDNS, []string{
		"k8s:k8s-app=kube-dns",
		"k8s:eks.amazonaws.com/component=kube-dns",
		fmt.Sprintf("k8s:%s=kube-system", api.PodNamespaceLabel),
		fmt.Sprintf("k8s:%s=kube-dns", api.PolicyLabelServiceAccount),
		fmt.Sprintf("k8s:%s=%s", api.PolicyLabelCluster, c.LocalClusterName()),
	})

	// kube-dns EKS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=coredns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:eks.amazonaws.com/component=coredns
	WellKnown.add(ReservedEKSCoreDNS, []string{
		"k8s:k8s-app=kube-dns",
		"k8s:eks.amazonaws.com/component=coredns",
		fmt.Sprintf("k8s:%s=kube-system", api.PodNamespaceLabel),
		fmt.Sprintf("k8s:%s=coredns", api.PolicyLabelServiceAccount),
		fmt.Sprintf("k8s:%s=%s", api.PolicyLabelCluster, c.LocalClusterName()),
	})

	// CoreDNS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=coredns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	WellKnown.add(ReservedCoreDNS, []string{
		"k8s:k8s-app=kube-dns",
		fmt.Sprintf("k8s:%s=kube-system", api.PodNamespaceLabel),
		fmt.Sprintf("k8s:%s=coredns", api.PolicyLabelServiceAccount),
		fmt.Sprintf("k8s:%s=%s", api.PolicyLabelCluster, c.LocalClusterName()),
	})

	// CiliumOperator labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-operator
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:name=cilium-operator
	//   k8s:io.cilium/app=operator
	//   k8s:io.cilium.k8s.policy.cluster=default
	WellKnown.add(ReservedCiliumOperator, []string{
		"k8s:name=cilium-operator",
		"k8s:io.cilium/app=operator",
		fmt.Sprintf("k8s:%s=%s", api.PodNamespaceLabel, c.CiliumNamespaceName()),
		fmt.Sprintf("k8s:%s=cilium-operator", api.PolicyLabelServiceAccount),
		fmt.Sprintf("k8s:%s=%s", api.PolicyLabelCluster, c.LocalClusterName()),
	})

	// cilium-etcd-operator labels
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-etcd-operator
	//   k8s:io.cilium/app=etcd-operator
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:name=cilium-etcd-operator
	WellKnown.add(ReservedCiliumEtcdOperator, []string{
		"k8s:name=cilium-etcd-operator",
		"k8s:io.cilium/app=etcd-operator",
		fmt.Sprintf("k8s:%s=%s", api.PodNamespaceLabel, c.CiliumNamespaceName()),
		fmt.Sprintf("k8s:%s=cilium-etcd-operator", api.PolicyLabelServiceAccount),
		fmt.Sprintf("k8s:%s=%s", api.PolicyLabelCluster, c.LocalClusterName()),
	})

	return len(WellKnown)
}

var (
	reservedIdentities = map[string]NumericIdentity{
		labels.IDNameHost:       ReservedIdentityHost,
		labels.IDNameWorld:      ReservedIdentityWorld,
		labels.IDNameUnmanaged:  ReservedIdentityUnmanaged,
		labels.IDNameHealth:     ReservedIdentityHealth,
		labels.IDNameInit:       ReservedIdentityInit,
		labels.IDNameRemoteNode: ReservedIdentityRemoteNode,
	}
	reservedIdentityNames = map[NumericIdentity]string{
		ReservedIdentityHost:       labels.IDNameHost,
		ReservedIdentityWorld:      labels.IDNameWorld,
		ReservedIdentityUnmanaged:  labels.IDNameUnmanaged,
		ReservedIdentityHealth:     labels.IDNameHealth,
		ReservedIdentityInit:       labels.IDNameInit,
		ReservedIdentityRemoteNode: labels.IDNameRemoteNode,
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
//    0-15: identity identifier
//   16-23: cluster identifier
//      24: LocalIdentityFlag: Indicates that the identity has a local scope
type NumericIdentity uint32

func ParseNumericIdentity(id string) (NumericIdentity, error) {
	nid, err := strconv.ParseUint(id, 0, 32)
	if err != nil {
		return NumericIdentity(0), err
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
func (id NumericIdentity) ClusterID() int {
	return int((uint32(id) >> 16) & 0xFF)
}

// GetAllReservedIdentities returns a list of all reserved numeric identities.
func GetAllReservedIdentities() []NumericIdentity {
	identities := []NumericIdentity{}
	for _, id := range reservedIdentities {
		identities = append(identities, id)
	}
	return identities
}

// IterateReservedIdentities iterates over all reservedIdentities and executes
// the given function for each key, value pair in reservedIdentities.
func IterateReservedIdentities(f func(key string, value NumericIdentity)) {
	for key, value := range reservedIdentities {
		f(key, value)
	}
}

// HasLocalScope returns true if the identity has a local scope
func (id NumericIdentity) HasLocalScope() bool {
	return (id & LocalIdentityFlag) != 0
}

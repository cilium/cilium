// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"strings"

	v2 "github.com/cilium/cilium/pkg/labels/v2"
)

const (
	// PathDelimiter is the delimiter used in the labels paths.
	PathDelimiter = v2.PathDelimiter

	// IDNameHost is the label used for the hostname ID.
	IDNameHost = v2.IDNameHost

	// IDNameRemoteNode is the label used to describe the
	// ReservedIdentityRemoteNode
	IDNameRemoteNode = v2.IDNameRemoteNode

	// IDNameWorld is the label used for the world ID.
	IDNameWorld = v2.IDNameWorld

	// IDNameWorldIPv4 is the label used for the world-ipv4 ID, to distinguish
	// it from world-ipv6 in dual-stack mode.
	IDNameWorldIPv4 = v2.IDNameWorldIPv4

	// IDNameWorldIPv6 is the label used for the world-ipv6 ID, to distinguish
	// it from world-ipv4 in dual-stack mode.
	IDNameWorldIPv6 = v2.IDNameWorldIPv6

	// IDNameCluster is the label used to identify an unspecified endpoint
	// inside the cluster
	IDNameCluster = v2.IDNameCluster

	// IDNameHealth is the label used for the local cilium-health endpoint
	IDNameHealth = v2.IDNameHealth

	// IDNameInit is the label used to identify any endpoint that has not
	// received any labels yet.
	IDNameInit = v2.IDNameInit

	// IDNameKubeAPIServer is the label used to identify the kube-apiserver. It
	// is part of the reserved identity 7 and it is also used in conjunction
	// with IDNameHost if the kube-apiserver is running on the local host.
	IDNameKubeAPIServer = v2.IDNameKubeAPIServer

	// IDNameEncryptedOverlay is the label used to identify encrypted overlay
	// traffic.
	//
	// It is part of the reserved identity 11 and signals that overlay traffic
	// with this identity must be IPSec encrypted before leaving the host.
	//
	// This identity should never be seen on the wire and is used only on the
	// local host.
	IDNameEncryptedOverlay = v2.IDNameEncryptedOverlay

	// IDNameIngress is the label used to identify Ingress proxies. It is part
	// of the reserved identity 8.
	IDNameIngress = v2.IDNameIngress

	// IDNameNone is the label used to identify no endpoint or other L3 entity.
	// It will never be assigned and this "label" is here for consistency with
	// other Entities.
	IDNameNone = v2.IDNameNone

	// IDNameUnmanaged is the label used to identify unmanaged endpoints
	IDNameUnmanaged = v2.IDNameUnmanaged

	// IDNameUnknown is the label used to to identify an endpoint with an
	// unknown identity.
	IDNameUnknown = v2.IDNameUnknown
)

var (
	// Empty is the canonical empty set of labels.
	Empty = Labels{}

	// LabelHealth is the label used for health.
	LabelHealth = v2.LabelHealth

	// LabelHost is the label used for the host endpoint.
	LabelHost = v2.LabelHost

	// LabelWorld is the label used for world.
	LabelWorld = v2.LabelWorld

	// LabelWorldIPv4 is the label used for world-ipv4.
	LabelWorldIPv4 = v2.LabelWorldIPv4

	// LabelWorldIPv6 is the label used for world-ipv6.
	LabelWorldIPv6 = v2.LabelWorldIPv6

	// LabelRemoteNode is the label used for remote nodes.
	LabelRemoteNode = v2.LabelRemoteNode

	// LabelKubeAPIServer is the label used for the kube-apiserver. See comment
	// on IDNameKubeAPIServer.
	LabelKubeAPIServer = v2.LabelKubeAPIServer

	// LabelIngress is the label used for Ingress proxies. See comment
	// on IDNameIngress.
	LabelIngress = v2.LabelIngress

	// LabelKeyFixedIdentity is the label that can be used to define a fixed
	// identity.
	LabelKeyFixedIdentity = v2.LabelKeyFixedIdentity
)

const (
	// LabelSourceUnspec is a label with unspecified source
	LabelSourceUnspec = v2.LabelSourceUnspec

	// LabelSourceAny is a label that matches any source
	LabelSourceAny = v2.LabelSourceAny

	// LabelSourceAnyKeyPrefix is prefix of a "any" label
	LabelSourceAnyKeyPrefix = v2.LabelSourceAnyKeyPrefix

	// LabelSourceK8s is a label imported from Kubernetes
	LabelSourceK8s = v2.LabelSourceK8s

	// LabelSourceK8sKeyPrefix is prefix of a Kubernetes label
	LabelSourceK8sKeyPrefix = v2.LabelSourceK8sKeyPrefix

	// LabelSourceContainer is a label imported from the container runtime
	LabelSourceContainer = v2.LabelSourceContainer

	// LabelSourceCNI is a label imported from the CNI plugin
	LabelSourceCNI = v2.LabelSourceCNI

	// LabelSourceReserved is the label source for reserved types.
	LabelSourceReserved = v2.LabelSourceReserved

	// LabelSourceCIDR is the label source for generated CIDRs.
	LabelSourceCIDR = v2.LabelSourceCIDR

	// LabelSourceCIDRGroup is the label source used for labels from CIDRGroups
	LabelSourceCIDRGroup = v2.LabelSourceCIDRGroup

	// LabelSourceNode is the label source for remote-nodes.
	LabelSourceNode = v2.LabelSourceNode

	// LabelSourceFQDN is the label source for IPs resolved by fqdn lookups
	LabelSourceFQDN = v2.LabelSourceFQDN

	// LabelSourceReservedKeyPrefix is the prefix of a reserved label
	LabelSourceReservedKeyPrefix = v2.LabelSourceReservedKeyPrefix

	// LabelSourceDirectory is the label source for policies read from files
	LabelSourceDirectory = v2.LabelSourceDirectory
)

// Label is the Cilium's representation of a container label.
type Label = v2.Label

// Labels is a map of labels where the map's key is the same as the label's key.
type Labels = v2.Labels

var (
	NewLabel                = v2.NewLabel
	Map2Labels              = v2.Map2Labels
	ParseLabel              = v2.ParseLabel
	ParseSelectLabel        = v2.ParseSelectLabel
	Merge                   = v2.Merge
	NewLabels               = v2.NewLabels
	FromSlice               = v2.FromSlice
	ParseLabels             = v2.ParseLabels
	NewLabelsFromSortedList = v2.NewLabelsFromSortedList
)

// GetCiliumKeyFrom returns the label's source and key from the an extended key
// in the format SOURCE:KEY.
func GetCiliumKeyFrom(extKey string) string {
	i := strings.IndexByte(extKey, PathDelimiter[0])
	if i >= 0 {
		return extKey[:i] + ":" + extKey[i+1:]
	}
	return LabelSourceAny + ":" + extKey
}

// GetExtendedKeyFrom returns the extended key of a label string.
// For example:
// `k8s:foo=bar` returns `k8s.foo`
// `container:foo=bar` returns `container.foo`
// `foo=bar` returns `any.foo=bar`
func GetExtendedKeyFrom(str string) string {
	src, next := v2.ParseSource(str, ':')
	if src == "" {
		src = LabelSourceAny
	}
	// Remove an eventually value
	i := strings.IndexByte(next, '=')
	if i >= 0 {
		return src + PathDelimiter + next[:i]
	}
	return src + PathDelimiter + next
}

// NewLabelsFromModel creates labels from string array.
func NewLabelsFromModel(base []string) Labels {
	return ParseLabels(base...)
}

// NewSelectLabelsFromModel parses a slice of strings and converts them
// into a set of selecting labels.
func NewSelectLabelsFromModel(base ...string) Labels {
	lbls := make([]Label, 0, len(base))
	for i := range base {
		lbls = append(lbls, ParseSelectLabel(base[i]))
	}
	return NewLabels(lbls...)
}

// generateLabelString generates the string representation of a label with
// the provided source, key, and value in the format "source:key=value".
func generateLabelString(source, key, value string) string {
	return source + ":" + key + "=" + value
}

// GenerateK8sLabelString generates the string representation of a label with
// the provided source, key, and value in the format "LabelSourceK8s:key=value".
func GenerateK8sLabelString(k, v string) string {
	return generateLabelString(LabelSourceK8s, k, v)
}

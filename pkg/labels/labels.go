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
	// LabelHealth is the label used for health.
	LabelHealth = NewLabels(NewLabel(IDNameHealth, "", LabelSourceReserved))

	// LabelHost is the label used for the host endpoint.
	LabelHost = NewLabels(NewLabel(IDNameHost, "", LabelSourceReserved))

	// LabelWorld is the label used for world.
	LabelWorld = NewLabels(NewLabel(IDNameWorld, "", LabelSourceReserved))

	// LabelWorldIPv4 is the label used for world-ipv4.
	LabelWorldIPv4 = NewLabels(NewLabel(IDNameWorldIPv4, "", LabelSourceReserved))

	// LabelWorldIPv6 is the label used for world-ipv6.
	LabelWorldIPv6 = NewLabels(NewLabel(IDNameWorldIPv6, "", LabelSourceReserved))

	// LabelRemoteNode is the label used for remote nodes.
	LabelRemoteNode = NewLabels(NewLabel(IDNameRemoteNode, "", LabelSourceReserved))

	// LabelKubeAPIServer is the label used for the kube-apiserver. See comment
	// on IDNameKubeAPIServer.
	LabelKubeAPIServer = NewLabels(NewLabel(IDNameKubeAPIServer, "", LabelSourceReserved))

	LabelKubeAPIServerExt = NewLabels(
		NewLabel(IDNameKubeAPIServer, "", LabelSourceReserved),
		NewLabel(IDNameWorld, "", LabelSourceReserved),
	)

	// LabelIngress is the label used for Ingress proxies. See comment
	// on IDNameIngress.
	LabelIngress = NewLabels(NewLabel(IDNameIngress, "", LabelSourceReserved))

	// LabelKeyFixedIdentity is the label that can be used to define a fixed
	// identity.
	LabelKeyFixedIdentity = "io.cilium.fixed-identity"
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

	// LabelSourceCIDRGroupKeyPrefix is the source as a k8s selector key prefix
	LabelSourceCIDRGroupKeyPrefix = v2.LabelSourceCIDRGroupKeyPrefix

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

// Labels is a set of labels
type Labels = v2.Labels

var Empty = v2.Empty

var NewLabels = v2.NewLabels

// NewLabel returns a new label from the given key, value and source. If source is empty,
// the default value will be LabelSourceUnspec. If key starts with '$', the source
// will be overwritten with LabelSourceReserved. If key contains ':', the value
// before ':' will be used as source if given source is empty, otherwise the value before
// ':' will be deleted and unused.
var NewLabel = v2.NewLabel

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

// Map2Labels transforms in the form: map[key(string)]value(string) into Labels. The
// source argument will overwrite the source written in the key of the given map.
// Example:
// l := Map2Labels(map[string]string{"k8s:foo": "bar"}, "cilium")
// fmt.Printf("%+v\n", l)
//
//	map[string]Label{"foo":Label{Key:"foo", Value:"bar", Source:"cilium"}}
var Map2Labels = v2.Map2Labels

// NewLabelsFromModel creates labels from string array.
func NewLabelsFromModel(base []string) Labels {
	lbls := make([]Label, 0, len(base))
	for _, v := range base {
		if lbl := ParseLabel(v); lbl.Key() != "" {
			lbls = append(lbls, lbl)
		}
	}
	return v2.NewLabels(lbls...)
}

// FromSlice creates labels from a slice of labels.
func FromSlice(labels []Label) Labels {
	return v2.NewLabels(labels...)
}

// NewLabelsFromSortedList returns labels based on the output of SortedList()
func NewLabelsFromSortedList(list string) Labels {
	return NewLabelsFromModel(strings.Split(list, ";"))
}

// NewSelectLabelArrayFromModel parses a slice of strings and converts them
// into an array of selecting labels, sorted by the key.
func NewSelectLabelArrayFromModel(base []string) LabelArray {
	lbls := make(LabelArray, 0, len(base))
	for i := range base {
		lbls = append(lbls, ParseSelectLabel(base[i]))
	}

	return lbls.Sort()
}

// ParseLabel returns the label representation of the given string. The str should be
// in the form of Source:Key=Value or Source:Key if Value is empty. It also parses short
// forms, for example: $host will be Label{Key: "host", Source: "reserved", Value: ""}.
var ParseLabel = v2.ParseLabel

// ParseSelectLabel returns a selecting label representation of the given
// string. Unlike ParseLabel, if source is unspecified, the source defaults to
// LabelSourceAny
var ParseSelectLabel = v2.ParseSelectLabel

// GenerateK8sLabelString generates the string representation of a label with
// the provided source, key, and value in the format "LabelSourceK8s:key=value".
var GenerateK8sLabelString = v2.GenerateK8sLabelString

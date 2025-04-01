// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sirupsen/logrus"
)

//
// Convenience methods for 'Label'
//

const (
	// PathDelimiter is the delimiter used in the labels paths.
	PathDelimiter = "."

	// IDNameHost is the label used for the hostname ID.
	IDNameHost = "host"

	// IDNameRemoteNode is the label used to describe the
	// ReservedIdentityRemoteNode
	IDNameRemoteNode = "remote-node"

	// IDNameWorld is the label used for the world ID.
	IDNameWorld = "world"

	// IDNameWorldIPv4 is the label used for the world-ipv4 ID, to distinguish
	// it from world-ipv6 in dual-stack mode.
	IDNameWorldIPv4 = "world-ipv4"

	// IDNameWorldIPv6 is the label used for the world-ipv6 ID, to distinguish
	// it from world-ipv4 in dual-stack mode.
	IDNameWorldIPv6 = "world-ipv6"

	// IDNameCluster is the label used to identify an unspecified endpoint
	// inside the cluster
	IDNameCluster = "cluster"

	// IDNameHealth is the label used for the local cilium-health endpoint
	IDNameHealth = "health"

	// IDNameInit is the label used to identify any endpoint that has not
	// received any labels yet.
	IDNameInit = "init"

	// IDNameKubeAPIServer is the label used to identify the kube-apiserver. It
	// is part of the reserved identity 7 and it is also used in conjunction
	// with IDNameHost if the kube-apiserver is running on the local host.
	IDNameKubeAPIServer = "kube-apiserver"

	// IDNameEncryptedOverlay is the label used to identify encrypted overlay
	// traffic.
	//
	// It is part of the reserved identity 11 and signals that overlay traffic
	// with this identity must be IPSec encrypted before leaving the host.
	//
	// This identity should never be seen on the wire and is used only on the
	// local host.
	IDNameEncryptedOverlay = "overlay-to-encrypt"

	// IDNameIngress is the label used to identify Ingress proxies. It is part
	// of the reserved identity 8.
	IDNameIngress = "ingress"

	// IDNameNone is the label used to identify no endpoint or other L3 entity.
	// It will never be assigned and this "label" is here for consistency with
	// other Entities.
	IDNameNone = "none"

	// IDNameUnmanaged is the label used to identify unmanaged endpoints
	IDNameUnmanaged = "unmanaged"

	// IDNameUnknown is the label used to to identify an endpoint with an
	// unknown identity.
	IDNameUnknown = "unknown"
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

	// LabelIngress is the label used for Ingress proxies. See comment
	// on IDNameIngress.
	LabelIngress = NewLabels(NewLabel(IDNameIngress, "", LabelSourceReserved))
)

// LabelKeyFixedIdentity is the label that can be used to define a fixed
// identity.
const LabelKeyFixedIdentity = "io.cilium.fixed-identity"

const (
	// LabelSourceUnspec is a label with unspecified source
	LabelSourceUnspec = "unspec"

	// LabelSourceAny is a label that matches any source
	LabelSourceAny = "any"

	// LabelSourceAnyKeyPrefix is prefix of a "any" label
	LabelSourceAnyKeyPrefix = LabelSourceAny + "."

	// LabelSourceK8s is a label imported from Kubernetes
	LabelSourceK8s = "k8s"

	// LabelSourceK8sKeyPrefix is prefix of a Kubernetes label
	LabelSourceK8sKeyPrefix = LabelSourceK8s + "."

	// LabelSourceContainer is a label imported from the container runtime
	LabelSourceContainer = "container"

	// LabelSourceCNI is a label imported from the CNI plugin
	LabelSourceCNI = "cni"

	// LabelSourceReserved is the label source for reserved types.
	LabelSourceReserved = "reserved"

	// LabelSourceCIDR is the label source for generated CIDRs.
	LabelSourceCIDR = "cidr"

	// LabelSourceCIDRGroup is the label source used for labels from CIDRGroups
	LabelSourceCIDRGroup = "cidrgroup"

	// LabelSourceNode is the label source for remote-nodes.
	LabelSourceNode = "node"

	// LabelSourceFQDN is the label source for IPs resolved by fqdn lookups
	LabelSourceFQDN = "fqdn"

	// LabelSourceReservedKeyPrefix is the prefix of a reserved label
	LabelSourceReservedKeyPrefix = LabelSourceReserved + "."

	// LabelSourceCIDRGroupKeyPrefix is the source as a k8s selector key prefix
	LabelSourceCIDRGroupKeyPrefix = LabelSourceCIDRGroup + "."

	// LabelSourceDirectory is the label source for policies read from files
	LabelSourceDirectory = "directory"
)

// NewLabel returns a new label from the given key, value and source. If source is empty,
// the default value will be LabelSourceUnspec. If key starts with '$', the source
// will be overwritten with LabelSourceReserved. If key contains ':', the value
// before ':' will be used as source if given source is empty, otherwise the value before
// ':' will be deleted and unused.
func NewLabel(key string, value string, source string) Label {
	var src string
	src, key = ParseSource(key, ':')
	if source == "" {
		if src == "" {
			source = LabelSourceUnspec
		} else {
			source = src
		}
	}
	if src == LabelSourceReserved && key == "" {
		key = value
		value = ""
	}

	var l Label
	if source == LabelSourceCIDR {
		c, err := LabelToPrefix(key)
		if err != nil {
			// FIXME what are these logs
			logrus.WithField("key", l.Key).WithError(err).Error("Failed to parse CIDR label: invalid prefix.")
			l = MakeLabel(key, value, source)
		} else {
			l = MakeCIDRLabel(key, value, source, &c)
		}
	} else {
		l = MakeLabel(key, value, source)
	}
	return l
}

func (l Label) DeepEqual(other *Label) bool {
	return l.Equal(*other)
}

func (l Label) CIDR() *netip.Prefix {
	return l.rep().cidr
}

// Has returns true label L contains target.
// target may be "looser" w.r.t source or cidr, i.e.
// "k8s:foo=bar".Has("any:foo=bar") is true
// "any:foo=bar".Has("k8s:foo=bar") is false
// "cidr:10.0.0.1/32".Has("cidr:10.0.0.0/24") is true
func (l Label) Has(target Label) bool {
	return l.HasKey(target) && l.Value() == target.Value()
}

// HasKey returns true if l has target's key.
// target may be "looser" w.r.t source or cidr, i.e.
// "k8s:foo=bar".HasKey("any:foo") is true
// "any:foo=bar".HasKey("k8s:foo") is false
// "cidr:10.0.0.1/32".HasKey("cidr:10.0.0.0/24") is true
// "cidr:10.0.0.0/24".HasKey("cidr:10.0.0.1/32") is false
func (l Label) HasKey(target Label) bool {
	if !target.IsAnySource() && l.Source() != target.Source() {
		return false
	}

	// Do cidr-aware matching if both sources are "cidr".
	if target.Source() == LabelSourceCIDR && l.Source() == LabelSourceCIDR {
		tc := target.CIDR()
		if tc == nil {
			v, err := LabelToPrefix(target.Key())
			if err != nil {
				tc = &v
			}
		}
		lc := l.CIDR()
		if lc == nil {
			v, err := LabelToPrefix(l.Key())
			if err != nil {
				lc = &v
			}
		}
		if tc != nil && lc != nil && tc.Bits() <= lc.Bits() && tc.Contains(lc.Addr()) {
			return true
		}
	}

	return l.Key() == target.Key()
}

func (l Label) HasCIDR(cidr netip.Prefix) bool {
	if l.Source() != LabelSourceCIDR {
		return false
	}
	lc := l.CIDR()
	if lc == nil {
		v, err := LabelToPrefix(l.Key())
		if err != nil {
			lc = &v
		}
	}
	return cidr.Bits() <= lc.Bits() && cidr.Contains(lc.Addr())
}

// IsValid returns true if Key != "".
func (l Label) IsValid() bool {
	return l.Key() != ""
}

// IsAnySource return if the label was set with source "any".
func (l Label) IsAnySource() bool {
	return l.Source() == LabelSourceAny
}

// IsReservedSource return if the label was set with source "Reserved".
func (l Label) IsReservedSource() bool {
	return l.Source() == LabelSourceReserved
}

// GetExtendedKey returns the key of a label with the source encoded.
func (l Label) GetExtendedKey() string {
	return l.Source() + PathDelimiter + l.Key()
}

func LabelToPrefix(key string) (netip.Prefix, error) {
	prefixStr := strings.Replace(key, "-", ":", -1)
	pfx, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to parse label prefix %s: %w", key, err)
	}
	return pfx, nil
}

// FormatForKVStore returns the label as a formatted string, ending in
// a semicolon
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS
// PART OF THE KEY IN THE KEY-VALUE STORE.
//
// Non-pointer receiver allows this to be called on a value in a map.
func (l Label) FormatForKVStore() []byte {
	// We don't care if the values already have a '='.
	//
	// We absolutely care that the final character is a semi-colon.
	// Identity allocation in the kvstore depends on this (see
	// kvstore.prefixMatchesKey())
	b := make([]byte, 0, len(l.Source())+len(l.Key())+len(l.Value())+3)
	buf := bytes.NewBuffer(b)
	l.FormatForKVStoreInto(buf)
	return buf.Bytes()
}

// FormatForKVStoreInto writes the label as a formatted string, ending in
// a semicolon into buf.
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS
// PART OF THE KEY IN THE KEY-VALUE STORE.
//
// Non-pointer receiver allows this to be called on a value in a map.
func (l Label) FormatForKVStoreInto(buf *bytes.Buffer) {
	buf.WriteString(l.Source())
	buf.WriteRune(':')
	buf.WriteString(l.Key())
	buf.WriteRune('=')
	buf.WriteString(l.Value())
	buf.WriteRune(';')
}

func (l Label) BuildString(sb *strings.Builder) {
	sb.WriteString(l.Source())
	sb.WriteString(":")
	sb.WriteString(l.Key())
	value := l.Value()
	if len(value) != 0 {
		sb.WriteString("=")
		sb.WriteString(value)
	}
}

func (l Label) BuildBytes(buf *bytes.Buffer) {
	buf.WriteString(l.Source())
	buf.WriteString(":")
	buf.WriteString(l.Key())
	value := l.Value()
	if len(value) != 0 {
		buf.WriteString("=")
		buf.WriteString(value)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/labels"
)

// maskedIPToLabelString is the base method for serializing an IP + prefix into
// a string that can be used for creating Labels and EndpointSelector objects.
//
// For IPv6 addresses, it converts ":" into "-" as EndpointSelectors don't
// support colons inside the name section of a label.
func maskedIPToLabel(ip netip.Addr, prefix int) labels.Label {
	ipStr := ip.String()
	ipNoColons := strings.Replace(ipStr, ":", "-", -1)

	// EndpointSelector keys can't start or end with a "-", so insert a
	// zero at the start or end if it would otherwise have a "-" at that
	// position.
	preZero := ""
	postZero := ""
	if ipNoColons[0] == '-' {
		preZero = "0"
	}
	if ipNoColons[len(ipNoColons)-1] == '-' {
		postZero = "0"
	}
	var str strings.Builder
	str.Grow(
		len(preZero) +
			len(ipNoColons) +
			len(postZero) +
			2 /*len of prefix*/ +
			1, /* '/' */
	)
	str.WriteString(preZero)
	str.WriteString(ipNoColons)
	str.WriteString(postZero)
	str.WriteRune('/')
	str.WriteString(strconv.Itoa(prefix))
	return labels.Label{Key: str.String(), Source: labels.LabelSourceCIDR}
}

// IPStringToLabel parses a string and returns it as a CIDR label.
//
// If ip is not a valid IP address or CIDR Prefix, returns an error.
func IPStringToLabel(ip string) (labels.Label, error) {
	// factored out of netip.ParsePrefix to avoid allocating an empty netip.Prefix in case it's
	// an IP and not a CIDR.
	i := strings.LastIndexByte(ip, '/')
	if i < 0 {
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil {
			return labels.Label{}, fmt.Errorf("%q is not an IP address: %w", ip, err)
		}
		return maskedIPToLabel(parsedIP, parsedIP.BitLen()), nil
	} else {
		parsedPrefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return labels.Label{}, fmt.Errorf("%q is not a CIDR: %w", ip, err)
		}
		return maskedIPToLabel(parsedPrefix.Masked().Addr(), parsedPrefix.Bits()), nil
	}
}

// GetCIDRLabels turns a CIDR into a set of labels representing the cidr itself
// and all broader CIDRS which include the specified CIDR in them. For example:
// CIDR: 10.0.0.0/8 =>
//
//	"cidr:10.0.0.0/8", "cidr:10.0.0.0/7", "cidr:8.0.0.0/6",
//	"cidr:8.0.0.0/5", "cidr:0.0.0.0/4, "cidr:0.0.0.0/3",
//	"cidr:0.0.0.0/2",  "cidr:0.0.0.0/1",  "cidr:0.0.0.0/0"
//
// The identity reserved:world is always added as it includes any CIDR.
func GetCIDRLabels(prefix netip.Prefix) labels.Labels {
	addr := prefix.Addr()
	ones := prefix.Bits()
	lbls := make(labels.Labels, 1 /* this CIDR */ +ones /* the prefixes */ +1 /*world label*/)

	// If ones is zero, then it's the default CIDR prefix /0 which should
	// just be regarded as reserved:world. In all other cases, we need
	// to generate the set of prefixes starting from the /0 up to the
	// specified prefix length.
	if ones == 0 {
		lbls[worldLabel.Key] = worldLabel
		return lbls
	}

	cache := cidrLabelsCache.Get().(map[netip.Prefix][]labels.Label)
	computeCIDRLabels(
		cache,
		lbls,
		nil, // avoid allocating space for the intermediate results until we need it
		addr,
		ones,
		0,
	)
	cidrLabelsCache.Put(cache)
	lbls[worldLabel.Key] = worldLabel

	return lbls
}

// cidrLabelsCache stores the partial computations for CIDR labels.
// This both avoids repeatedly computing the prefixes and makes sure the
// CIDR strings are reused to reduce memory usage.
// Stored in a sync.Pool to allow GC to garbage collect the cache if needed.
// With lots of contention, multiple cache maps might exist.
//
// Stores e.g. for prefix "10.0.0.0/8" the labels ["10.0.0.0/8", ..., "0.0.0.0/0"].
var cidrLabelsCache = sync.Pool{
	New: func() any { return make(map[netip.Prefix][]labels.Label) },
}

var worldLabel = labels.Label{Key: labels.IDNameWorld, Source: labels.LabelSourceReserved}

func computeCIDRLabels(cache map[netip.Prefix][]labels.Label, lbls labels.Labels, results []labels.Label, addr netip.Addr, ones, i int) []labels.Label {
	if i > ones {
		return results
	}

	prefix := netip.PrefixFrom(addr, i)

	if cachedLbls, ok := cache[prefix]; ok {
		for _, lbl := range cachedLbls {
			lbls[lbl.Key] = lbl
		}
		if results == nil {
			return cachedLbls
		} else {
			return append(results, cachedLbls...)
		}
	}

	// Compute the label for this prefix (e.g. "cidr:10.0.0.0/8")
	prefixLabel := maskedIPToLabel(prefix.Masked().Addr(), i)
	lbls[prefixLabel.Key] = prefixLabel

	// Keep computing the rest (e.g. "cidr:10.0.0.0/7", ...).
	results = computeCIDRLabels(
		cache,
		lbls,
		append(results, prefixLabel),
		addr, ones, i+1,
	)
	// Cache the resulting labels derived from this prefix, e.g. /8, /7, ...
	cache[prefix] = results[i:]

	return results
}

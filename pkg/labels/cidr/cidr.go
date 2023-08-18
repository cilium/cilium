// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/labels"
	lru "github.com/hashicorp/golang-lru"
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
func GetCIDRLabels(cidr *net.IPNet) labels.Labels {
	addr, _ := netip.AddrFromSlice(cidr.IP)
	ones, _ := cidr.Mask.Size()
	if ones == 0 {
		return worldLabels
	}
	prefix := netip.PrefixFrom(addr, ones)

	if lbls, ok := cidrLabelsCache.Get(prefix); ok {
		return lbls.(labels.Labels)
	}

	sliceCache := cidrLabelSliceCache.Get().(map[netip.Prefix][]labels.Label)
	result := make([]labels.Label, 1 /* this CIDR */ +ones /* prefixes */ +1 /* reserved:world */)
	computeCIDRLabels(sliceCache, result, addr, ones, 0)
	lbls := labels.FromSlice(result)
	cidrLabelSliceCache.Put(sliceCache)
	cidrLabelsCache.ContainsOrAdd(prefix, lbls)
	return lbls
}

// cidrLabelSliceCache for storing the partial computations for labels.
// Stored in a sync.Pool to allow GC to garbage collect the cache if needed.
// With lots of contention, multiple cache maps might exist.
//
// Stores e.g. for prefix "10.0.0.0/8" the labels ["10.0.0.0/8", ..., "0.0.0.0/0", "reserved:world"].
var cidrLabelSliceCache = sync.Pool{
	New: func() any { return make(map[netip.Prefix][]labels.Label) },
}

// cidrLabelsCache stores the computed labels for the given CIDR. Uses
// a sync.Map as with sync.Pool the hit rate would be too low to be effective.
var cidrLabelsCache, _ = lru.New(cidrLabelsCacheMaxSize)

const cidrLabelsCacheMaxSize = 16384

var (
	worldLabel  = labels.Label{Key: labels.IDNameWorld, Source: labels.LabelSourceReserved}
	worldLabels = labels.Labels{labels.IDNameWorld: worldLabel}
)

func computeCIDRLabels(cache map[netip.Prefix][]labels.Label, result []labels.Label, addr netip.Addr, ones, i int) {
	if i == ones+1 {
		result[i] = worldLabel
		return
	}

	prefix := netip.PrefixFrom(addr, i)

	if lbls, ok := cache[prefix]; ok {
		copy(result[i:], lbls)
		return
	}

	// Compute the label for this prefix (e.g. "cidr:10.0.0.0/8")
	result[i] = maskedIPToLabel(prefix.Masked().Addr(), i)

	// Compute the rest (e.g. "cidr:10.0.0.0/7", ...).
	computeCIDRLabels(cache, result, addr, ones, i+1)

	// Cache the resulting labels derived from this prefix, e.g. /8, /7, ...
	cache[prefix] = result[i:]
}

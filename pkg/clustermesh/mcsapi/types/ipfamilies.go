// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/slices"
)

func IPFamiliesToString(ipfamilies []corev1.IPFamily) string {
	return strings.Join(slices.Map(ipfamilies, func(ipf corev1.IPFamily) string { return string(ipf) }), ",")
}

func IPFamiliesFromString(s string) ([]corev1.IPFamily, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	ipfamilies := make([]corev1.IPFamily, 0, 2)
	for ipfamily := range strings.SplitSeq(s, ",") {
		ipfamily = strings.TrimSpace(ipfamily)
		switch ipfamily {
		case string(corev1.IPv4Protocol):
			ipfamilies = append(ipfamilies, corev1.IPv4Protocol)
		case string(corev1.IPv6Protocol):
			ipfamilies = append(ipfamilies, corev1.IPv6Protocol)
		default:
			return nil, fmt.Errorf("invalid IP family: %s", ipfamily)
		}
	}
	return ipfamilies, nil
}

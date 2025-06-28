// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testidentity

import "github.com/cilium/cilium/pkg/labels"

// These constants are used in tests across two packages, to ensure that label calculation
// for FQDN entries are consistent.
var FQDNLabelsV4 = labels.NewLabelsFromSortedList("fqdn:foo.com;reserved:world-ipv4")
var FQDNLabelsV6 = labels.NewLabelsFromSortedList("fqdn:foo.com;reserved:world-ipv6")
var FQDNLabelsSingleStack = labels.NewLabelsFromSortedList("fqdn:foo.com;reserved:world")

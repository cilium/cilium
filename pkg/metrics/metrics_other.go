// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package metrics

func enableIfIndexMetric() bool {
	return false
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

type IPsecAgent interface {
	AuthKeySize() int
	SPI() uint8
	StartBackgroundJobs(NodeHandler) error
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

var localBootID string

func GetBootID() string {
	return localBootID
}

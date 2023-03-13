// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

// enableIPForwarding on OS X and Darwin is not doing anything. It just exists
// to make compilation possible.
func enableIPForwarding() error {
	return nil
}

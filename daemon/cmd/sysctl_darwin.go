// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package cmd

// enableIPForwarding on OS X and Darwin is not doing anything. It just exists
// to make compilation possible.
func enableIPForwarding() error {
	return nil
}

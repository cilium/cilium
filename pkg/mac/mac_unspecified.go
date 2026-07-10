// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package mac

import "fmt"

func ReplaceMacAddressWithLinkName(ifName, macAddress string) error {
	return fmt.Errorf("not implemented")
}

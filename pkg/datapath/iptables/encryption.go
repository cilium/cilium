// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
)

// insertAcceptEncryptMark adds an accept rule to a `chain` on a `table` for traffic matching the encryption skb marks
func insertAcceptEncryptMark(ipt iptablesInterface, table, chain string) error {
	matchDecrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkDecrypt, linux_defaults.RouteMarkMask)
	matchEncrypt := fmt.Sprintf("%#08x/%#08x", linux_defaults.RouteMarkEncrypt, linux_defaults.RouteMarkMask)

	comment := "exclude encrypt/decrypt marks from " + table + " " + chain + " chain"

	if err := ipt.runProg([]string{
		"-t", table,
		"-A", chain,
		"-m", "mark", "--mark", matchEncrypt,
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT"}); err != nil {
		return err
	}

	return ipt.runProg([]string{
		"-t", table,
		"-A", chain,
		"-m", "mark", "--mark", matchDecrypt,
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT"})
}

// insertAcceptEncryptIpsec adds an accept rule to a `chain` on a `table` for traffic matching esp protocol
func insertAcceptEncryptIpsec(ipt iptablesInterface, table, chain string) error {
	comment := "exclude esp proto from " + table + " " + chain + " chain"

	return ipt.runProg([]string{
		"-t", table,
		"-A", chain,
		"-p", "esp",
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT"})
}

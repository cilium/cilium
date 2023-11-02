// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// The IPsec key custodian handles key-related initialisation tasks for the
// ipsec subsystem. It's an incremental step towards a more encompassing
// modularisation of the subsystem.
var Cell = cell.Module(
	"ipsec-key-custodian",
	"Handles initial key setup and knows the key size",

	cell.Provide(newKeyCustodian),
)

func newKeyCustodian(lc hive.Lifecycle, localNode *node.LocalNodeStore) types.IPsecKeyCustodian {
	ipsec := &keyCustodian{}
	lc.Append(ipsec)
	return ipsec
}

func (kc *keyCustodian) Start(hive.HookContext) error {
	if !option.Config.EncryptNode {
		DeleteIPsecEncryptRoute()
	}
	if !option.Config.EnableIPSec {
		return nil
	}

	var err error
	kc.authKeySize, kc.spi, err = LoadIPSecKeysFile(option.Config.IPSecKeyFile)
	if err != nil {
		return err
	}
	if err := SetIPSecSPI(kc.spi); err != nil {
		return err
	}

	kc.localNode.Update(func(n *node.LocalNode) {
		n.EncryptionKey = kc.spi
	})

	return nil
}

func (kc *keyCustodian) Stop(hive.HookContext) error {
	return nil
}

func (kc *keyCustodian) AuthKeySize() int {
	return kc.authKeySize
}

func (kc *keyCustodian) SPI() uint8 {
	return kc.spi
}

type keyCustodian struct {
	localNode   *node.LocalNodeStore
	authKeySize int
	spi         uint8
}

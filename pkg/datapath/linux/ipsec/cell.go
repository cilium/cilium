package ipsec

import (
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"ipsec",
	"IPsec",

	cell.Provide(newIPSec),
)

func newIPSec(lc hive.Lifecycle, localNode *node.LocalNodeStore) types.IPSec {
	ipsec := &ipsec{}
	lc.Append(ipsec)
	return ipsec
}

func (ipsec *ipsec) Start(hive.HookContext) error {
	if !option.Config.EncryptNode {
		DeleteIPsecEncryptRoute()
	}
	if !option.Config.EnableIPSec {
		return nil
	}

	var err error
	ipsec.authKeySize, ipsec.spi, err = LoadIPSecKeysFile(option.Config.IPSecKeyFile)
	if err != nil {
		return err
	}
	if err := SetIPSecSPI(ipsec.spi); err != nil {
		return err
	}

	ipsec.localNode.Update(func(n *node.LocalNode) {
		n.EncryptionKey = ipsec.spi
	})

	return nil
}

func (ipsec *ipsec) Stop(hive.HookContext) error {
	return nil
}

func (ipsec *ipsec) AuthKeySize() int {
	return ipsec.authKeySize
}

func (ipsec *ipsec) SPI() uint8 {
	return ipsec.spi
}

type ipsec struct {
	localNode   *node.LocalNodeStore
	authKeySize int
	spi         uint8
}

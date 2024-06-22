// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// The IPsec key custodian handles key-related initialisation tasks for the
// ipsec subsystem. It's an incremental step towards a more encompassing
// modularisation of the subsystem.
var Cell = cell.Module(
	"ipsec-key-custodian",
	"Handles initial key setup and knows the key size",

	cell.Provide(newKeyCustodian),
)

type custodianParameters struct {
	cell.In

	Log            *slog.Logger
	Health         cell.Health
	JobGroup       job.Group
	LocalNodeStore *node.LocalNodeStore
}

func newKeyCustodian(lc cell.Lifecycle, p custodianParameters) types.IPsecKeyCustodian {
	ipsec := &keyCustodian{
		log:       p.Log,
		localNode: p.LocalNodeStore,
		jobs:      p.JobGroup,
	}

	lc.Append(ipsec)
	return ipsec
}

func (kc *keyCustodian) Start(cell.HookContext) error {
	if !option.Config.EncryptNode {
		DeleteIPsecEncryptRoute(kc.log)
	}
	if !option.Config.EnableIPSec {
		return nil
	}

	var err error
	kc.authKeySize, kc.spi, err = LoadIPSecKeysFile(kc.log, option.Config.IPSecKeyFile)
	if err != nil {
		return err
	}
	if err := SetIPSecSPI(kc.log, kc.spi); err != nil {
		return err
	}

	kc.localNode.Update(func(n *node.LocalNode) {
		n.EncryptionKey = kc.spi
	})

	return nil
}

// StartBackgroundJobs starts the keyfile watcher and stale key reclaimer jobs.
func (kc *keyCustodian) StartBackgroundJobs(handler types.NodeHandler) error {
	if option.Config.EnableIPSec {
		if err := StartKeyfileWatcher(kc.log, kc.jobs, option.Config.IPSecKeyFile, handler); err != nil {
			return fmt.Errorf("failed to start IPsec keyfile watcher: %w", err)
		}

		kc.jobs.Add(job.Timer("stale-key-reclaimer", staleKeyReclaimer{kc.log}.onTimer, time.Minute))
	}

	return nil
}

func (kc *keyCustodian) Stop(cell.HookContext) error {
	return nil
}

func (kc *keyCustodian) AuthKeySize() int {
	return kc.authKeySize
}

func (kc *keyCustodian) SPI() uint8 {
	return kc.spi
}

type keyCustodian struct {
	log       *slog.Logger
	localNode *node.LocalNodeStore
	jobs      job.Group

	authKeySize int
	spi         uint8
}

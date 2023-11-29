// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"context"
	"fmt"
	"runtime/pprof"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
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

	Logger         logrus.FieldLogger
	Scope          cell.Scope
	JobRegistry    job.Registry
	LocalNodeStore *node.LocalNodeStore
}

func newKeyCustodian(lc hive.Lifecycle, p custodianParameters) types.IPsecKeyCustodian {
	group := p.JobRegistry.NewGroup(
		p.Scope,
		job.WithLogger(p.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "ipsec-key-custodian")),
	)

	ipsec := &keyCustodian{
		localNode: p.LocalNodeStore,
		jobs:      group,
	}

	lc.Append(ipsec)
	lc.Append(group)
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

// StartBackgroundJobs starts the keyfile watcher and stale key reclaimer jobs.
func (kc *keyCustodian) StartBackgroundJobs(_ context.Context, updater types.NodeUpdater, handler types.NodeHandler) error {
	if option.Config.EnableIPSec {
		if err := StartKeyfileWatcher(kc.jobs, option.Config.IPSecKeyFile, updater, handler); err != nil {
			return fmt.Errorf("failed to start IPsec keyfile watcher: %w", err)
		}

		kc.jobs.Add(job.Timer("stale-key-reclaimer", staleKeyReclaimer, time.Minute))
	}

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
	localNode *node.LocalNodeStore
	jobs      job.Group

	authKeySize int
	spi         uint8
}

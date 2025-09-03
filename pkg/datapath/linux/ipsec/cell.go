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

// The IPsec agent handles key-related initialisation tasks for the ipsec subsystem.
var Cell = cell.Module(
	"ipsec-agent",
	"Handles initial key setup and knows the key size",

	cell.Provide(newIPsecAgent),
)

type params struct {
	cell.In

	Log            *slog.Logger
	Health         cell.Health
	JobGroup       job.Group
	LocalNodeStore *node.LocalNodeStore
}

func newIPsecAgent(lc cell.Lifecycle, p params) types.IPsecAgent {
	ipsec := &Agent{
		log:       p.Log,
		localNode: p.LocalNodeStore,
		jobs:      p.JobGroup,
	}

	lc.Append(ipsec)
	return ipsec
}

func (a *Agent) Start(cell.HookContext) error {
	if !option.Config.EncryptNode {
		DeleteIPsecEncryptRoute(a.log)
	}
	if !option.Config.EnableIPSec {
		return nil
	}

	var err error
	a.authKeySize, a.spi, err = LoadIPSecKeysFile(option.Config.IPSecKeyFile)
	if err != nil {
		return err
	}
	if err := a.setIPSecSPI(a.spi); err != nil {
		return err
	}

	a.localNode.Update(func(n *node.LocalNode) {
		n.EncryptionKey = a.spi
	})

	return nil
}

// StartBackgroundJobs starts the keyfile watcher and stale key reclaimer jobs.
func (a *Agent) StartBackgroundJobs(handler types.NodeHandler) error {
	if option.Config.EnableIPSec {
		if err := a.startKeyfileWatcher(option.Config.IPSecKeyFile, handler); err != nil {
			return fmt.Errorf("failed to start IPsec keyfile watcher: %w", err)
		}

		a.jobs.Add(job.Timer("stale-key-reclaimer", staleKeyReclaimer{a.log}.onTimer, time.Minute))
	}

	return nil
}

func (a *Agent) Stop(cell.HookContext) error {
	return nil
}

func (a *Agent) AuthKeySize() int {
	return a.authKeySize
}

func (a *Agent) SPI() uint8 {
	return a.spi
}

type Agent struct {
	log       *slog.Logger
	localNode *node.LocalNodeStore
	jobs      job.Group

	authKeySize int
	spi         uint8
}

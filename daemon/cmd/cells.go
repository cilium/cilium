// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var (
	Agent = cell.Module(
		"agent",
		"Cilium Agent",

		Infrastructure,
		ControlPlane,
		Datapath,
	)

	// Infrastructure provides access and services to the outside.
	// A cell should live here instead of ControlPlane if it is not needed by
	// integrations tests, or needs to be mocked.
	Infrastructure = cell.Module(
		"infra",
		"Infrastructure",

		// Runs the gops agent, a tool to diagnose Go processes.
		gops.Cell(defaults.GopsPortAgent),

		// Provides Clientset, API for accessing Kubernetes objects.
		k8sClient.Cell,

		// Provide option.Config via hive so cells can depend on the agent config.
		cell.Provide(func() *option.DaemonConfig { return option.Config }),
	)

	// ControlPlane implement the per-node control functions. These are pure
	// business logic and depend on datapath or infrastructure to perform
	// actions. This separation enables non-privileged integration testing of
	// the control-plane.
	ControlPlane = cell.Module(
		"controlplane",
		"Control Plane",

		// LocalNodeStore holds onto the information about the local node and allows
		// observing changes to it.
		node.LocalNodeStoreCell,

		// daemonCell wraps the legacy daemon initialization and provides Promise[*Daemon].
		daemonCell,

		// The BGP Control Plane
		bgpv1.Cell,
	)

	// Datapath provides the privileged operations to apply control-plane
	// decision to the kernel.
	Datapath = cell.Module(
		"datapath",
		"Datapath",

		cell.Provide(
			newWireguardAgent,
			newDatapath,
		),
	)
)

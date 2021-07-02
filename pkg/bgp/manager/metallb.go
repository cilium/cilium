// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package speaker abstracts the BGP speaker controller from MetalLB. This
// package provides BGP announcements based on K8s object event handling.
package manager

import (
	"context"
	"os"

	bgpconfig "github.com/cilium/cilium/pkg/bgp/config"
	bgpk8s "github.com/cilium/cilium/pkg/bgp/k8s"
	bgplog "github.com/cilium/cilium/pkg/bgp/log"
	"github.com/cilium/cilium/pkg/option"

	metallballoc "go.universe.tf/metallb/pkg/allocator"
	metallbctl "go.universe.tf/metallb/pkg/controller"
	"go.universe.tf/metallb/pkg/k8s"
	"go.universe.tf/metallb/pkg/k8s/types"
	v1 "k8s.io/api/core/v1"
)

// Controller provides a method set for interfacing with a BGP Controller.
//
// This interface is heavily modeled after MetalLB's controller
// as it's the first BGP integration for Cilium's use cases.
//
// If other BGP integrations are desired, consider building out custom types
// and a more abstracted method set.
type Controller interface {
	SetBalancer(name string, srvRo *v1.Service, eps k8s.EpsOrSlices) types.SyncState
}

type metalLBController struct {
	c      *metallbctl.Controller
	logger *bgplog.Logger
}

func newMetalLBController(ctx context.Context) (Controller, error) {
	logger := &bgplog.Logger{Entry: log}
	c := &metallbctl.Controller{
		Client: bgpk8s.New(logger.Logger),
		IPs:    metallballoc.New(),
	}

	f, err := os.Open(option.Config.BGPConfigPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	config, err := bgpconfig.Parse(f)
	if err != nil {
		return nil, err
	}
	c.SetConfig(logger, config)

	return &metalLBController{
		c,
		logger,
	}, nil
}

func (c *metalLBController) SetBalancer(name string, srvRo *v1.Service, eps k8s.EpsOrSlices) types.SyncState {
	return c.c.SetBalancer(c.logger, name, srvRo, eps)
}

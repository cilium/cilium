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
package speaker

import (
	"context"
	"fmt"
	"os"

	bgpconfig "github.com/cilium/cilium/pkg/bgp/config"
	bgpk8s "github.com/cilium/cilium/pkg/bgp/k8s"
	bgplog "github.com/cilium/cilium/pkg/bgp/log"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	"go.universe.tf/metallb/pkg/k8s/types"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
)

// Speaker provides a method set for interfacing
// with a BGP speaker.
//
// This interface is heavily modeled after MetalLB's speaker
// as it's the first BGP integration for Cilium's use cases.
//
// If other BGP integrations are desired, consider building out custom types
// and a more abstracted method set.
type Speaker interface {
	SetService(name string, svc *metallbspr.Service, eps *metallbspr.Endpoints) types.SyncState
	SetNodeLabels(labels map[string]string) types.SyncState
	PeerSessions() []metallbspr.Session
}

// metalLBSpeaker implements the Speaker interface
// and is thin wrapper around the metallb controller proper.
type metalLBSpeaker struct {
	C      *metallbspr.Controller
	logger *bgplog.Logger
}

// newMetalLBSpeaker will create a new Speaker powered by
// a MetalLB BGP Speaker.
//
// This constructor expects option.Config.BGPConfigPath to point to
// a valid filesystem path where a MetalLB configure resides.
// It's an error if the config cannot be parsed.
//
// The MetalLB speaker will use the value of nodetypes.GetName() as
// its node identity.
func newMetalLBSpeaker(ctx context.Context) (Speaker, error) {
	logger := &bgplog.Logger{Entry: log}
	client := bgpk8s.New(logger.Logger)

	c, err := metallbspr.NewController(metallbspr.ControllerConfig{
		MyNode:        nodetypes.GetName(),
		Logger:        logger,
		SList:         nil, // BGP speaker doesn't use speakerlist
		DisableLayer2: true,
	})
	if err != nil {
		return nil, err
	}
	c.Client = client

	f, err := os.Open(option.Config.BGPConfigPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	config, err := bgpconfig.Parse(f)
	if err != nil {
		return nil, err
	}
	if ss := c.SetConfig(logger, config); ss == types.SyncStateError {
		return nil, fmt.Errorf("failed to set MetalLB config")
	}

	return metalLBSpeaker{
		C:      c,
		logger: logger,
	}, nil
}

func (m metalLBSpeaker) SetService(name string, svc *metallbspr.Service, eps *metallbspr.Endpoints) types.SyncState {
	return m.C.SetService(m.logger, name, svc, eps)
}
func (m metalLBSpeaker) SetNodeLabels(labels map[string]string) types.SyncState {
	return m.C.SetNodeLabels(m.logger, labels)
}
func (m metalLBSpeaker) PeerSessions() []metallbspr.Session {
	return m.C.PeerSessions()
}

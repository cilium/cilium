// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

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
	// SetService will announce the provided Service of type LoadBalancer to BGP peers.
	SetService(name string, svc *metallbspr.Service, eps *metallbspr.Endpoints) types.SyncState
	// SetNodeLabels will create or delete any BGP sessions given the provided labels
	// allow for this.
	//
	// The provided labels will be used to determine if the Speaker allows for BGP
	// peering.
	SetNodeLabels(labels map[string]string) types.SyncState
	// PeerSessions returns any active BGP sessions.
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

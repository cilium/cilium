// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"net/netip"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type processorParams struct {
	cell.In

	Logger          logrus.FieldLogger
	EndpointManager endpointmanager.EndpointManager
	GARPSender      Sender
	Config          Config
}

func newGARPProcessor(p processorParams) *processor {
	if !p.Config.EnableL2PodAnnouncements {
		return nil
	}

	gp := &processor{
		log:         p.Logger,
		garpSender:  p.GARPSender,
		endpointIPs: make(map[uint16]netip.Addr),
	}

	if p.EndpointManager != nil {
		p.EndpointManager.Subscribe(gp)
	}

	p.Logger.Info("initialised gratuitous arp processor")

	return gp
}

type processor struct {
	mu lock.Mutex

	log        logrus.FieldLogger
	garpSender Sender

	endpointIPs map[uint16]netip.Addr
}

var _ endpointmanager.Subscriber = &processor{}

// EndpointCreated implements endpointmanager.Subscriber
func (gp *processor) EndpointCreated(ep *endpoint.Endpoint) {
	gp.mu.Lock()
	defer gp.mu.Unlock()

	newIP := ep.IPv4
	if newIP.IsUnspecified() {
		return
	}

	oldIP, ok := gp.endpointIPs[ep.ID]
	if ok && oldIP == newIP {
		return
	}

	gp.endpointIPs[ep.ID] = newIP

	log := gp.log.WithFields(logrus.Fields{
		logfields.K8sPodName: ep.K8sPodName,
		logfields.IPAddr:     newIP,
	})

	if err := gp.garpSender.Send(newIP); err != nil {
		log.WithError(err).Warn("Failed to send gratuitous arp")
	} else {
		log.Debug("pod upsert gratuitous arp sent")
	}
}

// EndpointDeleted implements endpointmanager.Subscriber
func (gp *processor) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	gp.mu.Lock()
	defer gp.mu.Unlock()

	delete(gp.endpointIPs, ep.ID)
}

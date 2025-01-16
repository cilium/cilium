// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type processorParams struct {
	cell.In

	Logger          logging.FieldLogger
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

	log        logging.FieldLogger
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

	if err := gp.garpSender.Send(newIP); err != nil {
		gp.log.Warn(
			"Failed to send gratuitous arp",
			slog.Any(logfields.Error, err),
			slog.Any(logfields.K8sPodName, ep.K8sPodName),
			slog.Any(logfields.IPAddr, newIP))
	} else {
		gp.log.Debug(
			"pod upsert gratuitous arp sent",
			slog.Any(logfields.K8sPodName, ep.K8sPodName),
			slog.Any(logfields.IPAddr, newIP),
		)
	}
}

// EndpointDeleted implements endpointmanager.Subscriber
func (gp *processor) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	gp.mu.Lock()
	defer gp.mu.Unlock()

	delete(gp.endpointIPs, ep.ID)
}

// EndpointRestored implements endpointmanager.Subscriber.
func (gp *processor) EndpointRestored(ep *endpoint.Endpoint) {
	// No-op
}

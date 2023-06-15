// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"context"
	"net/netip"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// fakeSender mocks the GARP Sender, allowing for a feedback channel.
type fakeSender struct {
	sent chan netip.Addr
}

func (ms *fakeSender) Send(ip netip.Addr) error {
	ms.sent <- ip
	return nil
}

func (s *garpSuite) TestProcessorCell(c *C) {
	testIfaceName := "lo"

	// These allow us to inspect the state of the processor cell.
	garpSent := make(chan netip.Addr)
	var processorState *processor

	h := hive.New(cell.Module(
		"test-garp-processor-cell",
		"TestProcessorCell",

		cell.Config(Config{}),

		// Provide the mock GARP Sender cell, passing in feedback
		// channel.
		cell.Provide(func() Sender { return &fakeSender{sent: garpSent} }),
		cell.Provide(func() endpointmanager.EndpointManager { return nil }),
		cell.Provide(newGARPProcessor),

		// Force invocation.
		cell.Invoke(func(p *processor) {
			// Here we keep a reference to processor for inspection.
			processorState = p
		}),
	))

	// Apply the config so that the GARP cell will initialise.
	hive.AddConfigOverride(h, func(cfg *Config) {
		cfg.L2PodAnnouncementsInterface = testIfaceName
		cfg.EnableL2PodAnnouncements = true
	})

	// Everything is ready, start the cell.
	if err := h.Start(context.Background()); err != nil {
		c.Fatalf("Failed to start: %s", err)
	}

	// getGARPEvent is a helper func to see if a GARP packet would have
	// been sent. This assumes that if a GARP event should have been
	// sent, it would happen within the timeout window. Returns nil if
	// no GARP packet is sent.
	getGARPEvent := func() *netip.Addr {
		select {
		case e := <-garpSent:
			return &e
		case <-time.After(5 * time.Second):
			return nil
		}
	}

	// checkState is a helper function that asserts that the GARP
	// processor state matches the given desired state.
	checkState := func(desired map[uint16]string) {
		c.Assert(processorState.endpointIPs, HasLen, len(desired))
		desiredState := make(map[uint16]netip.Addr)
		for id, ip := range desired {
			desiredState[id] = netip.MustParseAddr(ip)
		}
		c.Assert(processorState.endpointIPs, checker.DeepEquals, desiredState)
	}

	// Create an endpoint. This should sent a GARP packet, and should
	// present an item in the state.
	go processorState.EndpointCreated(&endpoint.Endpoint{ID: 1, IPv4: netip.MustParseAddr("1.2.3.4")})
	garpEvent := getGARPEvent()
	c.Assert(garpEvent, NotNil) // GARP packet sent
	c.Assert(garpEvent.String(), Equals, "1.2.3.4")
	checkState(map[uint16]string{1: "1.2.3.4"})

	// Update the previous endpoint with the same IP. This should not send
	// any GARP packets or change the state.
	go processorState.EndpointCreated(&endpoint.Endpoint{ID: 1, IPv4: netip.MustParseAddr("1.2.3.4")})
	garpEvent = getGARPEvent()
	c.Assert(garpEvent, IsNil) // NO GARP packet sent
	checkState(map[uint16]string{1: "1.2.3.4"})

	// Update the previous endpoint with a new IP. This should send a new
	// GARP packet and the state should reflect the new IP.
	go processorState.EndpointCreated(&endpoint.Endpoint{ID: 1, IPv4: netip.MustParseAddr("4.3.2.1")})
	garpEvent = getGARPEvent()
	c.Assert(garpEvent, NotNil) // GARP packet sent
	c.Assert(garpEvent.String(), Equals, "4.3.2.1")
	checkState(map[uint16]string{1: "4.3.2.1"})

	// Delete the previous Pod. This should not send any GARP packets,
	// and the pod should no longer be present in the state.
	go processorState.EndpointDeleted(&endpoint.Endpoint{ID: 1, IPv4: netip.MustParseAddr("4.3.2.1")}, endpoint.DeleteConfig{})
	garpEvent = getGARPEvent()
	c.Assert(garpEvent, IsNil) // NO GARP packet sent
	checkState(map[uint16]string{})
}

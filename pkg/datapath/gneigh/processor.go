// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gneigh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type processorParams struct {
	cell.In

	Logger          *slog.Logger
	EndpointManager endpointmanager.EndpointManager
	Sender          Sender
	Config          Config
	DB              *statedb.DB
	Devices         statedb.Table[*tables.Device]
	JobGroup        job.Group
}

func newGNeighProcessor(p processorParams) (*processor, error) {
	if !p.Config.EnableL2PodAnnouncements {
		return nil, nil
	}

	var (
		devicesRegex *regexp.Regexp
		err          error
	)
	if p.Config.L2PodAnnouncementsInterfacePattern != "" {
		devicesRegex, err = regexp.Compile(p.Config.L2PodAnnouncementsInterfacePattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile devices regex: %w", err)
		}
	} else {
		return nil, fmt.Errorf("'--%s' must be set, when --%s=true", L2PodAnnouncementsInterfacePattern, EnableL2PodAnnouncements)
	}

	gp := &processor{
		params:       p,
		devicesRegex: devicesRegex,
		endpointIPs:  make(map[uint16]EndpointIPs),
	}

	p.JobGroup.Add(job.OneShot("device-updater", gp.deviceUpdater))

	// Check for nil so we can safely provide nil while testing.
	// During production, this should never be nil.
	if p.EndpointManager != nil {
		p.EndpointManager.Subscribe(gp)
	}

	return gp, nil
}

type EndpointIPs struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

type processor struct {
	params processorParams

	devicesRegex *regexp.Regexp

	mu             lock.Mutex
	sendInterfaces []Interface
	endpointIPs    map[uint16]EndpointIPs
}

func (gp *processor) deviceUpdater(ctx context.Context, health cell.Health) error {
	// Do not process device changes more than once every 5 seconds.
	// Based on nothing, seems a reasonable rate.
	rate := rate.NewLimiter(5*time.Second, 1)
	for {
		watch, err := gp.updateInterfaces()
		if err != nil {
			health.Degraded("failed to get interfaces", err)
		} else {
			health.OK(fmt.Sprintf("OK (%d interfaces)", len(gp.sendInterfaces)))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}

		if err := rate.Wait(ctx); err != nil {
			return err
		}
	}
}

func (gp *processor) updateInterfaces() (<-chan struct{}, error) {
	devices, watch := tables.SelectedDevices(gp.params.Devices, gp.params.DB.ReadTxn())

	var (
		sendInterfaces []Interface
		errs           error
	)

	for _, dev := range devices {
		if gp.devicesRegex.MatchString(dev.Name) {
			iface, err := gp.params.Sender.InterfaceByIndex(dev.Index)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to get interface %s: %w", dev.Name, err))
			}

			sendInterfaces = append(sendInterfaces, iface)
		}
	}

	gp.mu.Lock()
	gp.sendInterfaces = sendInterfaces
	gp.mu.Unlock()

	return watch, errs
}

var _ endpointmanager.Subscriber = &processor{}

func (gp *processor) send(ep *endpoint.Endpoint, ip netip.Addr, iface Interface) {
	if !ip.IsValid() {
		return
	}

	var (
		err   error
		proto string
	)

	if ip.Is4() {
		err = gp.params.Sender.SendArp(iface, ip, iface.HardwareAddr())
		proto = "ARP"
	} else {
		err = gp.params.Sender.SendNd(iface, ip, iface.HardwareAddr())
		proto = "ND"
	}

	if err != nil {
		gp.params.Logger.Warn(fmt.Sprintf("Failed to send gratuitous %s", proto),
			logfields.Error, err,
			logfields.K8sPodName, ep.K8sPodName,
			logfields.IPAddr, ip,
		)
	} else {
		gp.params.Logger.Debug(fmt.Sprintf("pod upsert gratuitous %s sent", proto),
			logfields.K8sPodName, ep.K8sPodName,
			logfields.IPAddr, ip,
		)
	}
}

// EndpointCreated implements endpointmanager.Subscriber
func (gp *processor) EndpointCreated(ep *endpoint.Endpoint) {
	gp.mu.Lock()
	defer gp.mu.Unlock()

	if !ep.IPv4.IsValid() && !ep.IPv6.IsValid() {
		gp.params.Logger.Warn("Endpoint doesn't have v4 nor v6 addresses. This is a bug!")
		return
	}

	newIPs := EndpointIPs{
		IPv4: ep.IPv4,
		IPv6: ep.IPv6,
	}

	oldIPs, ok := gp.endpointIPs[ep.ID]
	if ok && oldIPs.IPv4 == newIPs.IPv4 && oldIPs.IPv6 == newIPs.IPv6 {
		return
	}

	gp.endpointIPs[ep.ID] = newIPs

	for _, iface := range gp.sendInterfaces {
		gp.send(ep, newIPs.IPv4, iface)
		gp.send(ep, newIPs.IPv6, iface)
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

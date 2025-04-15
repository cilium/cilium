// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

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

func newGARPProcessor(p processorParams) (*processor, error) {
	if !p.Config.EnableL2PodAnnouncements {
		return nil, nil
	}

	if p.Config.L2PodAnnouncementsInterface != "" && p.Config.L2PodAnnouncementsInterfacePattern != "" {
		return nil, fmt.Errorf("only one of '--%s' and '--%s' can be set", L2PodAnnouncementsInterface, L2PodAnnouncementsInterfacePattern)
	}

	var (
		devicesRegex *regexp.Regexp
		err          error
	)
	if p.Config.L2PodAnnouncementsInterface != "" {
		devicesRegex, err = regexp.Compile("^" + p.Config.L2PodAnnouncementsInterface + "$")
		if err != nil {
			return nil, fmt.Errorf("failed to compile devices regex: %w", err)
		}

		// See https://github.com/cilium/cilium/issues/38229
		p.Logger.Warn("The '--" + L2PodAnnouncementsInterface + "' flag is deprecated and will be removed in a future release. Please use '--" + L2PodAnnouncementsInterfacePattern + "' instead.")

	} else if p.Config.L2PodAnnouncementsInterfacePattern != "" {
		devicesRegex, err = regexp.Compile(p.Config.L2PodAnnouncementsInterfacePattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile devices regex: %w", err)
		}

	} else {
		return nil, fmt.Errorf("'--%s' or '--%s' must be set, when --%s=true", L2PodAnnouncementsInterface, L2PodAnnouncementsInterfacePattern, EnableL2PodAnnouncements)
	}

	gp := &processor{
		params:       p,
		devicesRegex: devicesRegex,
		endpointIPs:  make(map[uint16]netip.Addr),
	}

	p.JobGroup.Add(job.OneShot("device-updater", gp.deviceUpdater))

	// Check for nil so we can safely provide nil while testing.
	// During production, this should never be nil.
	if p.EndpointManager != nil {
		p.EndpointManager.Subscribe(gp)
	}

	return gp, nil
}

type processor struct {
	params processorParams

	devicesRegex *regexp.Regexp

	mu             lock.Mutex
	sendInterfaces []Interface
	endpointIPs    map[uint16]netip.Addr
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

	for _, iface := range gp.sendInterfaces {
		if err := gp.params.Sender.Send(iface, newIP); err != nil {
			gp.params.Logger.Warn("Failed to send gratuitous arp",
				logfields.Error, err,
				logfields.K8sPodName, ep.K8sPodName,
				logfields.IPAddr, newIP,
			)
		} else {
			gp.params.Logger.Debug("pod upsert gratuitous arp sent",
				logfields.K8sPodName, ep.K8sPodName,
				logfields.IPAddr, newIP,
			)
		}
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

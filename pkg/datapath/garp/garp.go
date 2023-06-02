// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/arp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// GARPInterface is the interface used to send Gratuitous ARP messages.
	GARPInterface = "garp-interface"
)

var Cell = cell.Module(
	"garp",
	"GARP",

	cell.Provide(newGARPSender),

	// This cell can't have a default config, it's entirely env dependent.
	cell.Config(Config{}),
)

// Config contains the configuration for the GARP cell.
type Config struct {
	GARPInterface string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(GARPInterface, def.GARPInterface, "Interface used for sending gratuitous arp messages")
}

type Sender interface {
	Send(netip.Addr) error
}

func newGARPSender(log logrus.FieldLogger, cfg Config) (Sender, error) {
	if cfg.GARPInterface == "" {
		return nil, errors.New("gratuitous arp sender interface undefined")
	}

	iface, err := interfaceByName(cfg.GARPInterface)
	if err != nil {
		return nil, fmt.Errorf("gratuitous arp sender interface %q not found: %w", cfg.GARPInterface, err)
	}

	l := log.WithField(logfields.Interface, iface.Name)
	l.Info("initialised gratuitous arp sender")

	return &sender{
		logger: l,
		iface:  iface,
	}, nil
}

type sender struct {
	logger logrus.FieldLogger

	iface *net.Interface
}

// Send implements Sender
func (s *sender) Send(ip netip.Addr) error {
	err := send(s.iface, ip)
	if err == nil {
		s.logger.WithField(logfields.IPAddr, ip).Debug("sent gratuitous arp message")
	}

	return err
}

func SendOnInterface(ifaceName string, ip netip.Addr) error {
	iface, err := interfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("gratuitous arp sender interface %q not found: %w", ifaceName, err)
	}

	return send(iface, ip)
}

func send(iface *net.Interface, ip netip.Addr) error {
	arpClient, err := arp.Dial(iface)
	if err != nil {
		return fmt.Errorf("failed to send gARP message: %w", err)
	}
	defer arpClient.Close()

	if err := arpClient.Request(ip.AsSlice()); err != nil {
		return fmt.Errorf("failed to send gARP message: %w", err)
	}

	return nil
}

// interfaceByName get *net.Interface by name using netlink.
//
// The reason not to use net.InterfaceByName directly is to avoid potential
// deadlocks (#15051).
func interfaceByName(name string) (*net.Interface, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}

	return &net.Interface{
		Index:        link.Attrs().Index,
		MTU:          link.Attrs().MTU,
		Name:         link.Attrs().Name,
		Flags:        link.Attrs().Flags,
		HardwareAddr: link.Attrs().HardwareAddr,
	}, nil
}

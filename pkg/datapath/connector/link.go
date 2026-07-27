// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
)

// LinkConfig contains the GRO/GSO, MTU values and buffer margins to be configured on
// both sides of the created veth or netkit pair.
type LinkConfig struct {
	// EndpointID defines the container ID to which we are creating a new
	// linkpair. Set this if you want the connector to generate interface
	// names itself. Otherwise, set HostIfName and PeerIfName.
	EndpointID string

	// HostIfName defines the interface name as seen in the host namespace.
	HostIfName string

	// PeerIfName defines the interface name as seen in the container namespace.
	PeerIfName string

	// PeerNamespace defines the namespace the peer link should be moved into.
	PeerNamespace *netns.NetNS

	GROIPv6MaxSize int
	GSOIPv6MaxSize int

	GROIPv4MaxSize int
	GSOIPv4MaxSize int

	DeviceMTU      int
	DeviceHeadroom uint16
	DeviceTailroom uint16
}

type LinkPair interface {
	GetHostLink() netlink.Link
	GetPeerLink() netlink.Link
	GetMode() Mode
	Delete() error
}

func NewLinkPair(
	log *slog.Logger,
	mode Mode,
	cfg LinkConfig,
	sysctl sysctl.Sysctl,
) (*linkPair, error) {
	log.Debug("Creating new linkpair",
		logfields.LinkConfig, cfg,
		logfields.DatapathMode, mode,
	)

	finalPeerIfName := cfg.PeerIfName
	if cfg.EndpointID != "" {
		// If we have an EndpointID, we derive interface names from this.
		cfg.HostIfName = Endpoint2IfName(cfg.EndpointID)
		cfg.PeerIfName = Endpoint2TempIfName(cfg.EndpointID)
	} else {
		// If we don't have an EndpointID to derive interface names from, we must
		// be given both the host and peer ifnames.
		if cfg.HostIfName == "" || cfg.PeerIfName == "" {
			return nil, fmt.Errorf("invalid EndpointID")
		}
	}

	var hostLink, peerLink netlink.Link
	var err error

	switch mode {
	case ModeVeth:
		hostLink, peerLink, err = setupVethPair(
			log,
			cfg,
			sysctl,
		)

	case ModeNetkit:
		hostLink, peerLink, err = setupNetkitPair(
			log,
			cfg,
			false,
			sysctl,
		)
	case ModeNetkitL2:
		hostLink, peerLink, err = setupNetkitPair(
			log,
			cfg,
			true,
			sysctl,
		)
	default:
		err = fmt.Errorf("invalid linkpair mode: %s", mode)
	}
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			if err := netlink.LinkDel(hostLink); err != nil {
				log.Warn("failed to cleanup link pair",
					logfields.Device, hostLink.Attrs().Name,
					logfields.Error, err,
				)
			}
		}
	}()

	err = configureLinkPair(hostLink, peerLink, cfg)
	if err != nil {
		return nil, err
	}

	// Move peer link to any specified namespace
	if cfg.PeerNamespace != nil {
		nsfd := cfg.PeerNamespace.FD()

		err := netlink.LinkSetNsFd(peerLink, nsfd)
		if err != nil {
			return nil, fmt.Errorf("failed to move device %q to namespace: %w",
				peerLink.Attrs().Name, err)
		}
	}

	// Rename the peer link, if we generated a temporary name earlier
	finalPeerIfName, err = renameIfNeeded(finalPeerIfName, cfg.PeerIfName, cfg.PeerNamespace)
	if err != nil {
		return nil, err
	}

	if err := markOwned(cfg.PeerNamespace, finalPeerIfName); err != nil {
		log.Warn("unable to mark peer link cilium ownership",
			logfields.Error, err,
			logfields.Name, finalPeerIfName,
		)
	}

	// re-generate the peer Link as the previous one is likely stale
	if cfg.PeerNamespace != nil {
		if err := cfg.PeerNamespace.Do(func() error {
			peerLink, err = safenetlink.LinkByName(finalPeerIfName)
			return err
		}); err != nil {
			return nil, err
		}
	} else {
		peerLink, err = safenetlink.LinkByName(finalPeerIfName)
		if err != nil {
			return nil, err
		}
	}

	pair := &linkPair{
		hostLink: hostLink,
		peerLink: peerLink,
		mode:     mode,
	}
	return pair, nil
}

func configureLinkPair(hostSide, endpointSide netlink.Link, cfg LinkConfig) error {
	var err error
	epIfName := endpointSide.Attrs().Name
	hostIfName := hostSide.Attrs().Name

	if err = netlink.LinkSetMTU(hostSide, cfg.DeviceMTU); err != nil {
		return fmt.Errorf("unable to set MTU to %q: %w", hostIfName, err)
	}

	if err = netlink.LinkSetMTU(endpointSide, cfg.DeviceMTU); err != nil {
		return fmt.Errorf("unable to set MTU to %q: %w", epIfName, err)
	}

	if err = netlink.LinkSetUp(hostSide); err != nil {
		return fmt.Errorf("unable to bring up %q: %w", hostIfName, err)
	}

	if cfg.GROIPv6MaxSize > 0 {
		if err = netlink.LinkSetGROMaxSize(hostSide, cfg.GROIPv6MaxSize); err != nil {
			return fmt.Errorf("unable to set GRO max size to %q: %w",
				hostIfName, err)
		}
		if err = netlink.LinkSetGROMaxSize(endpointSide, cfg.GROIPv6MaxSize); err != nil {
			return fmt.Errorf("unable to set GRO max size to %q: %w",
				epIfName, err)
		}
	}

	if cfg.GSOIPv6MaxSize > 0 {
		if err = netlink.LinkSetGSOMaxSize(hostSide, cfg.GSOIPv6MaxSize); err != nil {
			return fmt.Errorf("unable to set GSO max size to %q: %w",
				hostIfName, err)
		}
		if err = netlink.LinkSetGSOMaxSize(endpointSide, cfg.GSOIPv6MaxSize); err != nil {
			return fmt.Errorf("unable to set GSO max size to %q: %w",
				epIfName, err)
		}
	}

	if cfg.GROIPv4MaxSize > 0 {
		if err = netlink.LinkSetGROIPv4MaxSize(hostSide, cfg.GROIPv4MaxSize); err != nil {
			return fmt.Errorf("unable to set GRO max size to %q: %w",
				hostIfName, err)
		}
		if err = netlink.LinkSetGROIPv4MaxSize(endpointSide, cfg.GROIPv4MaxSize); err != nil {
			return fmt.Errorf("unable to set GRO max size to %q: %w",
				epIfName, err)
		}
	}

	if cfg.GSOIPv4MaxSize > 0 {
		if err = netlink.LinkSetGSOIPv4MaxSize(hostSide, cfg.GSOIPv4MaxSize); err != nil {
			return fmt.Errorf("unable to set GSO max size to %q: %w",
				hostIfName, err)
		}
		if err = netlink.LinkSetGSOIPv4MaxSize(endpointSide, cfg.GSOIPv4MaxSize); err != nil {
			return fmt.Errorf("unable to set GSO max size to %q: %w",
				epIfName, err)
		}
	}
	return nil
}

func DeleteLinkPair(cfg LinkConfig) error {
	if cfg.EndpointID != "" {
		cfg.HostIfName = Endpoint2IfName(cfg.EndpointID)
	} else if cfg.HostIfName == "" {
		return fmt.Errorf("invalid EndpointID")
	}

	if err := link.DeleteByName(cfg.HostIfName); err != nil {
		return fmt.Errorf("error deleting link: %w", err)
	}

	return nil
}

type linkPair struct {
	hostLink netlink.Link
	peerLink netlink.Link
	mode     Mode
}

func (lp *linkPair) GetHostLink() netlink.Link {
	return lp.hostLink
}

func (lp *linkPair) GetPeerLink() netlink.Link {
	return lp.peerLink
}

func (lp *linkPair) GetMode() Mode {
	return lp.mode
}

func (lp *linkPair) Delete() error {
	if lp.hostLink != nil {
		if err := netlink.LinkDel(lp.hostLink); err != nil {
			return fmt.Errorf("delete linkpair %q failed: %w", lp.hostLink.Attrs().Name, err)
		}
		*lp = linkPair{}
	}
	return nil
}

// renameIfNeeded renames the link, if needed. also returns the desired interface name.
func renameIfNeeded(finalName, currentName string, ns *netns.NetNS) (string, error) {
	// nsDo runs `f` within namespace context if necessary
	nsDo := func(f func() error) error {
		if ns != nil {
			return ns.Do(f)
		}

		return f()
	}

	// if finalName is empty OR it matches currentName, just try returning
	// the existing link.
	if finalName == "" || finalName == currentName {
		return currentName, nil
	}

	rename := func() error {
		err := link.Rename(currentName, finalName)
		if err != nil {
			return fmt.Errorf("failed to rename link from %s to %s: %w", currentName, finalName, err)
		}

		return nil
	}

	if err := nsDo(rename); err != nil {
		return "", err
	}

	return finalName, nil
}

// markOwned marks interface at `ifName` inside `ns` context
// as cilium owned by writing to the link altname.
func markOwned(ns *netns.NetNS, ifName string) error {
	markFunc := func() error {
		return link.AddAltName(ifName, CniAltName(ifName))
	}

	if ns != nil {
		return ns.Do(markFunc)
	}

	return markFunc()
}

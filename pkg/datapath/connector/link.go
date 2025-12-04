// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func NewLinkPair(
	log *slog.Logger,
	mode types.ConnectorMode,
	cfg types.LinkConfig,
	sysctl sysctl.Sysctl,
) (*LinkPair, error) {
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
	case types.ConnectorModeVeth:
		hostLink, peerLink, err = SetupVethWithNames(
			log,
			cfg.HostIfName,
			cfg.PeerIfName,
			cfg,
			sysctl,
		)

	case types.ConnectorModeNetkit:
		hostLink, peerLink, err = SetupNetkitWithNames(
			log,
			cfg.HostIfName,
			cfg.PeerIfName,
			cfg,
			false,
			sysctl,
		)
	case types.ConnectorModeNetkitL2:
		hostLink, peerLink, err = SetupNetkitWithNames(
			log,
			cfg.HostIfName,
			cfg.PeerIfName,
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
	if finalPeerIfName != "" && finalPeerIfName != cfg.PeerIfName {
		rename := func() error {
			if err := link.Rename(cfg.PeerIfName, finalPeerIfName); err != nil {
				return fmt.Errorf("failed to rename link from %s to %s: %w", cfg.PeerIfName, finalPeerIfName, err)
			}
			return nil
		}

		if cfg.PeerNamespace != nil {
			err = cfg.PeerNamespace.Do(func() error { return rename() })
		} else {
			err = rename()
		}
		if err != nil {
			return nil, err
		}
	}

	pair := &LinkPair{
		hostLink: hostLink,
		peerLink: peerLink,
		mode:     mode,
	}
	return pair, nil
}

func DeleteLinkPair(cfg types.LinkConfig) error {
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

type LinkPair struct {
	hostLink netlink.Link
	peerLink netlink.Link
	mode     types.ConnectorMode
}

func (lp *LinkPair) GetHostLink() netlink.Link {
	return lp.hostLink
}

func (lp *LinkPair) GetPeerLink() netlink.Link {
	return lp.peerLink
}

func (lp *LinkPair) GetMode() types.ConnectorMode {
	return lp.mode
}

func (lp *LinkPair) Delete() error {
	if lp.hostLink != nil {
		if err := netlink.LinkDel(lp.hostLink); err != nil {
			return fmt.Errorf("delete linkpair %q failed: %w", lp.hostLink.Attrs().Name, err)
		}
		*lp = LinkPair{}
	}
	return nil
}

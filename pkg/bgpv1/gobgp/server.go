// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	apb "google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var (
	// GoBGPIPv6Family is a read-only pointer to a gobgp.Family structure
	// representing IPv6 address family.
	GoBGPIPv6Family = &gobgp.Family{
		Afi:  gobgp.Family_AFI_IP6,
		Safi: gobgp.Family_SAFI_UNICAST,
	}
	// GoBGPIPv4Family is a read-only pointer to a gobgp.Family structure
	// representing IPv4 address family.
	GoBGPIPv4Family = &gobgp.Family{
		Afi:  gobgp.Family_AFI_IP,
		Safi: gobgp.Family_SAFI_UNICAST,
	}
)

// Advertisement is a container object which associates a net.IPNet with a
// gobgp.Path.
//
// The `Net` field makes comparing this Advertisement with another IPNet encoded
// prefixes simple.
//
// The `Path` field is a gobgp.Path object which can be forwarded to our server's
// WithdrawPath method, making withdrawing an advertised route simple.
type Advertisement struct {
	Net  *net.IPNet
	Path *gobgp.Path
}

// ServerWithConfig is a container for grouping a gobgp BgpServer with the
// Cilium's BGP control plane related configuration.
//
// It exports a method set for manipulating the BgpServer. However, this
// struct is a dumb object. The calling code is required to keep the BgpServer's
// configuration and associated configuration fields in sync.
type ServerWithConfig struct {
	// a gobgp backed BgpServer configured in accordance to the accompanying
	// CiliumBGPVirtualRouter configuration.
	Server *server.BgpServer
	// The CiliumBGPVirtualRouter configuration which drives the configuration
	// of the above BgpServer.
	//
	// If this field is nil it means the above BgpServer has had no
	// configuration applied to it.
	Config *v2alpha1api.CiliumBGPVirtualRouter
	// Holds any announced PodCIDR routes.
	PodCIDRAnnouncements []Advertisement
}

// NewServerWithConfig will start an underlying BgpServer utilizing startReq
// for its initial configuration.
//
// The returned ServerWithConfig has a nil CiliumBGPVirtualRouter config, and is
// ready to be provided to ReconcileBGPConfig.
//
// Canceling the provided context will kill the BgpServer along with calling the
// underlying BgpServer's Stop() method.
func NewServerWithConfig(ctx context.Context, startReq *gobgp.StartBgpRequest) (*ServerWithConfig, error) {
	logger := NewServerLogger(log.Logger, startReq.Global.Asn)

	s := server.NewBgpServer(server.LoggerOption(logger))
	go s.Serve()

	if err := s.StartBgp(ctx, startReq); err != nil {
		return nil, fmt.Errorf("failed starting BGP server: %w", err)
	}

	// will log out any peer changes.
	watchRequest := &gobgp.WatchEventRequest{
		Peer: &gobgp.WatchEventRequest_Peer{},
	}
	err := s.WatchEvent(ctx, watchRequest, func(r *gobgp.WatchEventResponse) {
		if p := r.GetPeer(); p != nil && p.Type == gobgp.WatchEventResponse_PeerEvent_STATE {
			logger.l.Info(p)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure logging for virtual router with local-asn %v: %w", startReq.Global.Asn, err)
	}

	return &ServerWithConfig{
		Server:               s,
		Config:               nil,
		PodCIDRAnnouncements: []Advertisement{},
	}, nil
}

// AddNeighbor will add the CiliumBGPNeighbor to the gobgp.BgpServer, creating
// a BGP peering connection.
func (sc *ServerWithConfig) AddNeighbor(ctx context.Context, n *v2alpha1api.CiliumBGPNeighbor) error {
	// cilium neighbor uses CIDR string, gobgp neighbor uses IP string, convert.
	var ip net.IP
	var err error
	if ip, _, err = net.ParseCIDR(n.PeerAddress); err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerReq := &gobgp.AddPeerRequest{
		Peer: &gobgp.Peer{
			Conf: &gobgp.PeerConf{
				NeighborAddress: ip.String(),
				PeerAsn:         uint32(n.PeerASN),
			},
			// tells the peer we are capable of unicast IPv4 and IPv6
			// advertisements.
			AfiSafis: []*gobgp.AfiSafi{
				{
					Config: &gobgp.AfiSafiConfig{
						Family: GoBGPIPv4Family,
					},
				},
				{
					Config: &gobgp.AfiSafiConfig{
						Family: GoBGPIPv6Family,
					},
				},
			},
		},
	}
	if err = sc.Server.AddPeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while adding peer %v %v: %w", n.PeerAddress, n.PeerASN, err)
	}
	return nil
}

// RemoveNeighbor will remove the CiliumBGPNeighbor from the gobgp.BgpServer,
// disconnecting the BGP peering connection.
func (sc *ServerWithConfig) RemoveNeighbor(ctx context.Context, n *v2alpha1api.CiliumBGPNeighbor) error {
	// cilium neighbor uses CIDR string, gobgp neighbor uses IP string, convert.
	var ip net.IP
	var err error
	if ip, _, err = net.ParseCIDR(n.PeerAddress); err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerReq := &gobgp.DeletePeerRequest{
		Address: ip.String(),
	}
	if err := sc.Server.DeletePeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
	}
	return nil
}

// AdvertisePath will advertise the provided IP network to any existing and all
// subsequently added Neighbors currently peered with this BgpServer.
//
// `ip` can be an ipv4 or ipv6 and this method will handle the differences
// between MP BGP and BGP.
//
// `cstate` provides the IPv6 and IPv4 next host addresses which `must` be
// Cilium's externally reachable IPv6 or IPv4 address.
//
// It is an error to advertise an IPv6 path when no IPv6 address is configured
// on this Cilium node, selfsame for IPv4.
//
// An Advertisement is returned which may be passed to WithdrawPath to remove
// this Advertisement.
func (sc *ServerWithConfig) AdvertisePath(ctx context.Context, ip *net.IPNet, cstate *agent.ControlPlaneState) (Advertisement, error) {
	var err error
	var path *gobgp.Path
	origin, _ := apb.New(&gobgp.OriginAttribute{
		Origin: 0,
	})
	switch {
	case ip.IP.To4() != nil:
		if cstate.IPv4.IsUnspecified() {
			return Advertisement{}, fmt.Errorf("cannot advertise IPv4 path %v, control plane has no configured IPv4 address for next hop", ip.String())
		}
		prefixLen, _ := ip.Mask.Size()
		nlri, _ := apb.New(&gobgp.IPAddressPrefix{
			PrefixLen: uint32(prefixLen),
			Prefix:    ip.IP.String(),
		})
		nextHop, _ := apb.New(&gobgp.NextHopAttribute{
			NextHop: cstate.IPv4.String(),
		})
		path = &gobgp.Path{
			Family: GoBGPIPv4Family,
			Nlri:   nlri,
			Pattrs: []*apb.Any{nextHop, origin},
		}
		_, err = sc.Server.AddPath(ctx, &gobgp.AddPathRequest{
			Path: path,
		})
	case ip.IP.To16() != nil:
		if cstate.IPv6.IsUnspecified() {
			return Advertisement{}, fmt.Errorf("cannot advertise IPv6 path %v, control plane has no configured IPv6 address for next hop", ip.String())
		}
		prefixLen, _ := ip.Mask.Size()
		nlri, _ := apb.New(&gobgp.IPAddressPrefix{
			PrefixLen: uint32(prefixLen),
			Prefix:    ip.IP.String(),
		})
		nlriAttrs, _ := apb.New(&gobgp.MpReachNLRIAttribute{ // MP BGP NLRI
			Family:   GoBGPIPv6Family,
			NextHops: []string{cstate.IPv6.String()},
			Nlris:    []*apb.Any{nlri},
		})
		path = &gobgp.Path{
			Family: GoBGPIPv6Family,
			Nlri:   nlri,
			Pattrs: []*apb.Any{nlriAttrs, origin},
		}
		_, err = sc.Server.AddPath(ctx, &gobgp.AddPathRequest{
			Path: path,
		})
	default:
		return Advertisement{}, fmt.Errorf("provided IP returned nil for both IPv4 and IPv6 lengths: %v", len(ip.IP))
	}
	if err != nil {
		return Advertisement{}, err
	}
	return Advertisement{
		ip,
		path,
	}, err
}

// WithdrawPath withdraws an Advertisement produced by AdvertisePath from this
// BgpServer.
func (sc *ServerWithConfig) WithdrawPath(ctx context.Context, advert Advertisement) error {
	err := sc.Server.DeletePath(ctx, &gobgp.DeletePathRequest{
		Family: advert.Path.Family,
		Path:   advert.Path,
	})
	return err
}

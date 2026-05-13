// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgryski/go-farm"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	tspb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Unlimited batch size by default
const defaultListPathBatchSize = math.MaxUint64

type server struct {
	bgpServer  *BgpServer
	shared     *sharedData
	grpcServer *grpc.Server
	hosts      string
	api.UnimplementedGoBgpServiceServer
}

func newAPIserver(b *BgpServer, shared *sharedData, g *grpc.Server, hosts string) *server {
	grpc.EnableTracing = false
	s := &server{
		bgpServer:  b,
		shared:     shared,
		grpcServer: g,
		hosts:      hosts,
	}
	api.RegisterGoBgpServiceServer(g, s)
	return s
}

func (s *server) serve() error {
	var wg sync.WaitGroup
	l := []net.Listener{}
	var err error
	for _, host := range strings.Split(s.hosts, ",") {
		network, address := parseHost(host)
		var lis net.Listener
		lis, err = net.Listen(network, address)
		if err != nil {
			s.bgpServer.logger.Warn("listen failed",
				slog.String("Topic", "grpc"),
				slog.String("Key", host),
				slog.String("Error", err.Error()),
			)
			break
		}
		l = append(l, lis)
	}
	if err != nil {
		for _, lis := range l {
			lis.Close()
		}
		return err
	}

	wg.Add(len(l))
	serve := func(lis net.Listener) {
		defer wg.Done()
		err := s.grpcServer.Serve(lis)
		if err != nil {
			s.bgpServer.logger.Warn("accept failed",
				slog.String("Topic", "grpc"),
				slog.String("Key", lis.Addr().String()),
				slog.String("Error", err.Error()),
			)
		}
	}

	for _, lis := range l {
		go serve(lis)
	}
	wg.Wait()
	return nil
}

func (s *server) ListDynamicNeighbor(r *api.ListDynamicNeighborRequest, stream api.GoBgpService_ListDynamicNeighborServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(dn *api.DynamicNeighbor) {
		if sendErr = stream.Send(&api.ListDynamicNeighborResponse{DynamicNeighbor: dn}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListDynamicNeighbor(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func (s *server) ListPeerGroup(r *api.ListPeerGroupRequest, stream api.GoBgpService_ListPeerGroupServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(pg *api.PeerGroup) {
		if sendErr = stream.Send(&api.ListPeerGroupResponse{PeerGroup: pg}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListPeerGroup(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func parseHost(host string) (string, string) {
	const unixScheme = "unix://"
	if strings.HasPrefix(host, unixScheme) {
		return "unix", host[len(unixScheme):]
	}
	return "tcp", host
}

func (s *server) ListPeer(r *api.ListPeerRequest, stream api.GoBgpService_ListPeerServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(p *api.Peer) {
		if sendErr = stream.Send(&api.ListPeerResponse{Peer: p}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListPeer(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func toApiState(s oc.RpkiValidationResultType) api.ValidationState {
	switch s {
	case oc.RPKI_VALIDATION_RESULT_TYPE_VALID:
		return api.ValidationState_VALIDATION_STATE_VALID
	case oc.RPKI_VALIDATION_RESULT_TYPE_INVALID:
		return api.ValidationState_VALIDATION_STATE_INVALID
	case oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND:
		return api.ValidationState_VALIDATION_STATE_NOT_FOUND
	case oc.RPKI_VALIDATION_RESULT_TYPE_NONE:
		return api.ValidationState_VALIDATION_STATE_NONE
	default:
		return api.ValidationState_VALIDATION_STATE_UNSPECIFIED
	}
}

func toApiReason(r table.RpkiValidationReasonType) api.Validation_Reason {
	switch r {
	case table.RPKI_VALIDATION_REASON_TYPE_NONE:
		return api.Validation_REASON_NONE
	case table.RPKI_VALIDATION_REASON_TYPE_AS:
		return api.Validation_REASON_ASN
	case table.RPKI_VALIDATION_REASON_TYPE_LENGTH:
		return api.Validation_REASON_LENGTH
	default:
		return api.Validation_REASON_UNSPECIFIED
	}
}

func newValidationFromTableStruct(v *table.Validation) *api.Validation {
	if v == nil {
		return &api.Validation{}
	}
	return &api.Validation{
		State:           toApiState(v.Status),
		Reason:          toApiReason(v.Reason),
		Matched:         newRoaListFromTableStructList(v.Matched),
		UnmatchedAsn:    newRoaListFromTableStructList(v.UnmatchedAs),
		UnmatchedLength: newRoaListFromTableStructList(v.UnmatchedLength),
	}
}

func toPathAPI(binNlri []byte, binPattrs [][]byte, anyNlri *api.NLRI, anyPattrs []*api.Attribute, path *apiutil.Path) *api.Path {
	p := &api.Path{
		Nlri:               anyNlri,
		Pattrs:             anyPattrs,
		Age:                tspb.New(time.Unix(path.Age, 0)),
		IsWithdraw:         path.Withdrawal,
		Family:             &api.Family{Afi: api.Family_Afi(path.Family.Afi()), Safi: api.Family_Safi(path.Family.Safi())},
		Stale:              path.Stale,
		IsFromExternal:     path.IsFromExternal,
		NoImplicitWithdraw: path.NoImplicitWithdraw,
		IsNexthopInvalid:   path.IsNexthopInvalid,
		Identifier:         path.RemoteID,
		LocalIdentifier:    path.LocalID,
		NlriBinary:         binNlri,
		PattrsBinary:       binPattrs,
		SourceAsn:          path.PeerASN,
		// ListPath API fields only
		Best:            path.Best,
		SendMaxFiltered: path.SendMaxFiltered,
		Filtered:        path.Filtered,
		Validation:      path.Validation,
	}
	if path.PeerID.IsValid() {
		p.SourceId = path.PeerID.String()
	}
	if path.PeerAddress.IsValid() {
		p.NeighborIp = path.PeerAddress.String()
	}
	return p
}

func toPathApi(path *apiutil.Path, onlyBinary, nlriBinary, attributeBinary bool) *api.Path {
	var (
		anyNlri   *api.NLRI
		anyPattrs []*api.Attribute
	)
	nlri := path.Nlri
	if !onlyBinary {
		if nlri != nil {
			anyNlri, _ = apiutil.MarshalNLRI(nlri)
		}
		anyPattrs, _ = apiutil.MarshalPathAttributes(path.Attrs)
	}
	var binNlri []byte
	if nlri != nil && (onlyBinary || nlriBinary) {
		binNlri, _ = nlri.Serialize()
	}
	var binPattrs [][]byte
	if onlyBinary || attributeBinary {
		pa := path.Attrs
		binPattrs = make([][]byte, 0, len(pa))
		for _, a := range pa {
			b, e := a.Serialize()
			if e == nil {
				binPattrs = append(binPattrs, b)
			}
		}
	}
	return toPathAPI(binNlri, binPattrs, anyNlri, anyPattrs, path)
}

func getValidation(v map[*table.Path]*table.Validation, p *table.Path) *table.Validation {
	if v == nil {
		return nil
	} else {
		return v[p]
	}
}

func (s *server) listPath(ctx context.Context, r *api.ListPathRequest, fn func(*api.Destination)) error {
	family := bgp.Family(0)
	if r.Family != nil {
		family = bgp.NewFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))
	}
	req := apiutil.ListPathRequest{
		TableType:      r.TableType,
		Name:           r.Name,
		Family:         family,
		SortType:       r.SortType,
		EnableFiltered: r.EnableFiltered,
	}
	if r.TableType != api.TableType_TABLE_TYPE_UNSPECIFIED && r.TableType != api.TableType_TABLE_TYPE_VRF {
		for _, p := range r.Prefixes {
			req.Prefixes = append(req.Prefixes, &apiutil.LookupPrefix{
				Prefix:       p.Prefix,
				RD:           p.Rd,
				LookupOption: apiutil.LookupOptionFromAPI(p.Type),
			})
		}
	}

	err := s.bgpServer.ListPath(req, func(prefix bgp.NLRI, paths []*apiutil.Path) {
		if ctx.Err() != nil {
			return
		}
		d := api.Destination{
			Prefix: prefix.String(),
			Paths:  make([]*api.Path, len(paths)),
		}
		for i, path := range paths {
			d.Paths[i] = toPathApi(path, r.EnableOnlyBinary, r.EnableNlriBinary, r.EnableAttributeBinary)
		}
		fn(&d)
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (s *server) ListPath(r *api.ListPathRequest, stream api.GoBgpService_ListPathServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	batchSize := r.BatchSize
	if batchSize == 0 {
		batchSize = defaultListPathBatchSize
	}
	l := make([]*api.Destination, 0)
	send := func() error {
		for _, d := range l {
			if err := stream.Send(&api.ListPathResponse{Destination: d}); err != nil {
				return err
			}
		}
		return nil
	}
	var sendErr error
	err := s.listPath(ctx, r, func(d *api.Destination) {
		l = append(l, d)
		if uint64(len(l)) <= batchSize {
			return
		}
		if sendErr = send(); sendErr != nil {
			cancel()
			return
		}
		l = l[:0]
	})
	if sendErr != nil {
		return sendErr
	}
	if err != nil {
		return err
	}
	return send()
}

func (s *server) watchEvent(ctx context.Context, r *api.WatchEventRequest, fn func(*api.WatchEventResponse, time.Time)) error {
	opts := make([]WatchOption, 0)
	if r.GetPeer() != nil {
		opts = append(opts, WatchPeer())
	}
	if t := r.GetTable(); t != nil {
		for _, filter := range t.Filters {
			switch filter.Type {
			case api.WatchEventRequest_Table_Filter_TYPE_BEST:
				opts = append(opts, WatchBestPath(filter.Init))
			case api.WatchEventRequest_Table_Filter_TYPE_ADJIN:
				opts = append(opts, WatchUpdate(filter.Init, filter.PeerAddress, filter.PeerGroup))
			case api.WatchEventRequest_Table_Filter_TYPE_POST_POLICY:
				opts = append(opts, WatchPostUpdate(filter.Init, filter.PeerAddress, filter.PeerGroup))
			case api.WatchEventRequest_Table_Filter_TYPE_EOR:
				opts = append(opts, WatchEor(filter.Init))
			default:
				return status.Errorf(codes.InvalidArgument, "unknown filter type %s", filter.Type)
			}
		}
	}
	if len(opts) == 0 {
		return status.Errorf(codes.InvalidArgument, "no events to watch")
	}
	simpleSend := func(paths []*api.Path, when time.Time) {
		fn(&api.WatchEventResponse{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{Paths: paths}}}, when)
	}
	err := s.bgpServer.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnPathUpdate: func(pathList []*apiutil.Path, timestamp time.Time) {
			paths := make([]*api.Path, 0, r.BatchSize)
			for _, path := range pathList {
				paths = append(paths, toPathApi(path, false, false, false))
				if r.BatchSize > 0 && len(paths) > int(r.BatchSize) {
					simpleSend(paths, timestamp)
					paths = make([]*api.Path, 0, r.BatchSize)
				}
			}
			simpleSend(paths, timestamp)
		},
		OnBestPath: func(pathList []*apiutil.Path, timestamp time.Time) {
			pl := make([]*api.Path, 0, r.BatchSize)
			for _, path := range pathList {
				pl = append(pl, toPathApi(path, false, false, false))
				if r.BatchSize > 0 && len(pl) > int(r.BatchSize) {
					simpleSend(pl, timestamp)
					pl = make([]*api.Path, 0, r.BatchSize)
				}
			}
			simpleSend(pl, timestamp)
		},
		OnPathEor: func(path *apiutil.Path, timestamp time.Time) {
			p := toPathApi(path, false, false, false)
			simpleSend([]*api.Path{p}, timestamp)
		},
		OnPeerUpdate: func(peer *apiutil.WatchEventMessage_PeerEvent, timestamp time.Time) {
			p := peer.Peer
			remoteCaps, err := apiutil.MarshalCapabilities(p.State.RemoteCap)
			if err != nil {
				remoteCaps = []*api.Capability{}
			}
			fn(&api.WatchEventResponse{
				Event: &api.WatchEventResponse_Peer{
					Peer: &api.WatchEventResponse_PeerEvent{
						Type: api.WatchEventResponse_PeerEvent_Type(peer.Type),
						Peer: &api.Peer{
							Conf: &api.PeerConf{
								PeerAsn:           p.Conf.PeerASN,
								LocalAsn:          p.Conf.LocalASN,
								NeighborAddress:   p.Conf.NeighborAddress.String(),
								NeighborInterface: p.Conf.NeighborInterface,
							},
							State: &api.PeerState{
								PeerAsn:         p.State.PeerASN,
								LocalAsn:        p.State.LocalASN,
								NeighborAddress: p.State.NeighborAddress.String(),
								SessionState:    api.PeerState_SessionState(int(p.State.SessionState) + 1),
								AdminState:      p.State.AdminState,
								RouterId:        p.State.RouterID.String(),
								RemoteCap:       remoteCaps,
							},
							Transport: &api.Transport{
								LocalAddress: p.Transport.LocalAddress.String(),
								LocalPort:    p.Transport.LocalPort,
								RemotePort:   p.Transport.RemotePort,
							},
						},
					},
				},
			}, timestamp)
		},
	}, opts...)
	if err != nil {
		return status.Errorf(codes.Aborted, "failed to watch event: %v", err)
	}
	return status.Error(codes.OK, "watch event started")
}

func (s *server) WatchEvent(r *api.WatchEventRequest, stream api.GoBgpService_WatchEventServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	err := s.watchEvent(ctx, r, func(rsp *api.WatchEventResponse, _ time.Time) {
		if err := stream.Send(rsp); err != nil {
			cancel()
			return
		}
	})
	if err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func (s *server) ResetPeer(ctx context.Context, r *api.ResetPeerRequest) (*api.ResetPeerResponse, error) {
	return &api.ResetPeerResponse{}, s.bgpServer.ResetPeer(ctx, r)
}

func (s *server) ShutdownPeer(ctx context.Context, r *api.ShutdownPeerRequest) (*api.ShutdownPeerResponse, error) {
	return &api.ShutdownPeerResponse{}, s.bgpServer.ShutdownPeer(ctx, r)
}

func (s *server) EnablePeer(ctx context.Context, r *api.EnablePeerRequest) (*api.EnablePeerResponse, error) {
	return &api.EnablePeerResponse{}, s.bgpServer.EnablePeer(ctx, r)
}

func (s *server) DisablePeer(ctx context.Context, r *api.DisablePeerRequest) (*api.DisablePeerResponse, error) {
	return &api.DisablePeerResponse{}, s.bgpServer.DisablePeer(ctx, r)
}

func (s *server) SetPolicies(ctx context.Context, r *api.SetPoliciesRequest) (*api.SetPoliciesResponse, error) {
	return &api.SetPoliciesResponse{}, s.bgpServer.SetPolicies(ctx, r)
}

func newRoutingPolicyFromApiStruct(arg *api.SetPoliciesRequest) (*oc.RoutingPolicy, error) {
	policyDefinitions := make([]oc.PolicyDefinition, 0, len(arg.Policies))
	for _, p := range arg.Policies {
		pd, err := newConfigPolicyFromApiStruct(p)
		if err != nil {
			return nil, err
		}
		policyDefinitions = append(policyDefinitions, *pd)
	}

	definedSets, err := newConfigDefinedSetsFromApiStruct(arg.DefinedSets)
	if err != nil {
		return nil, err
	}

	return &oc.RoutingPolicy{
		DefinedSets:       *definedSets,
		PolicyDefinitions: policyDefinitions,
	}, nil
}

func api2Path(resource api.TableType, path *api.Path, isWithdraw bool) (*table.Path, error) {
	var pi *table.PeerInfo
	var nlri bgp.NLRI
	var nexthop netip.Addr

	if path.SourceAsn != 0 {
		pi = &table.PeerInfo{
			AS: path.SourceAsn,
			ID: netip.MustParseAddr(path.SourceId),
		}
	}

	nlri, err := apiutil.GetNativeNlri(path)
	if err != nil {
		return nil, err
	}

	attrList, err := apiutil.GetNativePathAttributes(path)
	if err != nil {
		return nil, err
	}

	// TODO (sbezverk) At this poinnt nlri and path attributes are converted to native mode
	// need to check if update with SR Policy nlri comes with mandatory route distinguisher
	// extended community or NO_ADVERTISE community, with Tunnel Encapsulation Attribute 23
	// and tunnel type 15. If it is not the case ignore update and log an error.

	pattrs := make([]bgp.PathAttributeInterface, 0)
	seen := make(map[bgp.BGPAttrType]struct{})
	for _, attr := range attrList {
		attrType := attr.GetType()
		if _, ok := seen[attrType]; !ok {
			seen[attrType] = struct{}{}
		} else {
			return nil, fmt.Errorf("duplicated path attribute type: %d", attrType)
		}

		switch a := attr.(type) {
		case *bgp.PathAttributeNextHop:
			nexthop = a.Value
		case *bgp.PathAttributeMpReachNLRI:
			if len(a.Value) == 0 {
				return nil, fmt.Errorf("invalid mp reach attribute")
			}
			nexthop = a.Nexthop
		default:
			pattrs = append(pattrs, attr)
		}
	}

	if !path.IsWithdraw && !nexthop.IsValid() {
		return nil, fmt.Errorf("nexthop not found")
	}
	rf := bgp.NewFamily(uint16(path.Family.Afi), uint8(path.Family.Safi))
	if resource != api.TableType_TABLE_TYPE_VRF && rf == bgp.RF_IPv4_UC && nexthop.Is4() {
		pa, _ := bgp.NewPathAttributeNextHop(nexthop)
		pattrs = append(pattrs, pa)
	} else {
		attr, _ := bgp.NewPathAttributeMpReachNLRI(rf, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
		pattrs = append(pattrs, attr)
	}

	doWithdraw := isWithdraw || path.IsWithdraw
	newPath := table.NewPath(rf, pi, bgp.PathNLRI{NLRI: nlri, ID: path.Identifier}, doWithdraw, pattrs, time.Now(), path.NoImplicitWithdraw)
	if !doWithdraw {
		total := bytes.NewBuffer(make([]byte, 0))
		for _, a := range newPath.GetPathAttrs() {
			if a.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
				continue
			}
			b, _ := a.Serialize()
			total.Write(b)
		}
		newPath.SetHash(farm.Hash64(total.Bytes()))
	}
	newPath.SetIsFromExternal(path.IsFromExternal)
	return newPath, nil
}

func api2apiutilPath(path *api.Path) (*apiutil.Path, error) {
	nlri, err := apiutil.GetNativeNlri(path)
	if err != nil {
		return nil, fmt.Errorf("invalid nlri: %w", err)
	}
	attrs, err := apiutil.GetNativePathAttributes(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path attributes: %w", err)
	}
	// source is optional
	src, _ := netip.ParseAddr(path.SourceId)
	neighbor, _ := netip.ParseAddr(path.NeighborIp)
	p := &apiutil.Path{
		Family:             bgp.NewFamily(uint16(path.Family.Afi), uint8(path.Family.Safi)),
		Nlri:               nlri,
		Attrs:              attrs,
		Age:                path.Age.GetSeconds(),
		Best:               path.Best,
		Stale:              path.Stale,
		Withdrawal:         path.IsWithdraw,
		PeerASN:            path.SourceAsn,
		PeerID:             src,
		PeerAddress:        neighbor,
		IsFromExternal:     path.IsFromExternal,
		NoImplicitWithdraw: path.NoImplicitWithdraw,
		LocalID:            path.LocalIdentifier,
		RemoteID:           path.Identifier,
	}
	if p.PeerASN != 0 && !p.PeerID.IsValid() {
		return nil, fmt.Errorf("source ID must be set correctly %v", p.PeerID)
	}
	return p, nil
}

func (s *server) AddPath(ctx context.Context, r *api.AddPathRequest) (*api.AddPathResponse, error) {
	if r.Path == nil {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}
	var err error
	var uuidBytes []byte
	p, err := api2apiutilPath(r.Path)
	if err != nil {
		return &api.AddPathResponse{}, fmt.Errorf("invalid path: %w", err)
	}
	path, err := s.bgpServer.AddPath(apiutil.AddPathRequest{
		VRFID: r.VrfId,
		Paths: []*apiutil.Path{p},
	})
	if err != nil {
		return &api.AddPathResponse{}, err
	}

	id := path[0].UUID
	uuidBytes, err = id.MarshalBinary()
	return &api.AddPathResponse{Uuid: uuidBytes}, err
}

func (s *server) DeletePath(ctx context.Context, r *api.DeletePathRequest) (*api.DeletePathResponse, error) {
	deletePath := func(ctx context.Context, r *api.DeletePathRequest) error {
		var pathList []*apiutil.Path
		if len(r.Uuid) == 0 {
			if r.Path != nil {
				path, err := api2apiutilPath(r.Path)
				if err != nil {
					return err
				}
				pathList = []*apiutil.Path{path}
			}
		}
		if len(r.Uuid) > 0 {
			// Delete locally generated path which has the given UUID
			id, _ := uuid.FromBytes(r.Uuid)
			if err := s.bgpServer.DeletePath(apiutil.DeletePathRequest{VRFID: r.VrfId, UUIDs: []uuid.UUID{id}}); err != nil {
				return err
			}
		} else if len(pathList) == 0 {
			// Delete all locally generated paths
			var family bgp.Family
			if r.Family != nil {
				family = bgp.NewFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))
			}
			if err := s.bgpServer.DeletePath(apiutil.DeletePathRequest{VRFID: r.VrfId, DeleteAll: true, DeleteFamily: &family}); err != nil {
				return err
			}
		} else {
			if err := s.bgpServer.DeletePath(apiutil.DeletePathRequest{VRFID: r.VrfId, Paths: pathList}); err != nil {
				return err
			}
		}
		return nil
	}
	return &api.DeletePathResponse{}, deletePath(ctx, r)
}

func (s *server) EnableMrt(ctx context.Context, r *api.EnableMrtRequest) (*api.EnableMrtResponse, error) {
	return &api.EnableMrtResponse{}, s.bgpServer.EnableMrt(ctx, r)
}

func (s *server) DisableMrt(ctx context.Context, r *api.DisableMrtRequest) (*api.DisableMrtResponse, error) {
	return &api.DisableMrtResponse{}, s.bgpServer.DisableMrt(ctx, r)
}

func (s *server) AddPathStream(stream api.GoBgpService_AddPathStreamServer) error {
	for {
		arg, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if arg.TableType != api.TableType_TABLE_TYPE_GLOBAL && arg.TableType != api.TableType_TABLE_TYPE_VRF {
			return fmt.Errorf("unsupported resource: %s", arg.TableType)
		}
		pathList := make([]*table.Path, 0, len(arg.Paths))
		for _, apiPath := range arg.Paths {
			if path, err := api2Path(arg.TableType, apiPath, apiPath.IsWithdraw); err != nil {
				return err
			} else {
				pathList = append(pathList, path)
			}
		}
		err = s.bgpServer.addPathStream(arg.VrfId, pathList)
		if err != nil {
			return err
		}
	}
	return stream.SendAndClose(&api.AddPathStreamResponse{})
}

func (s *server) AddBmp(ctx context.Context, r *api.AddBmpRequest) (*api.AddBmpResponse, error) {
	return &api.AddBmpResponse{}, s.bgpServer.AddBmp(ctx, r)
}

func (s *server) DeleteBmp(ctx context.Context, r *api.DeleteBmpRequest) (*api.DeleteBmpResponse, error) {
	return &api.DeleteBmpResponse{}, s.bgpServer.DeleteBmp(ctx, r)
}

func (s *server) ListBmp(r *api.ListBmpRequest, stream api.GoBgpService_ListBmpServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(rsp *api.ListBmpResponse_BmpStation) {
		if sendErr = stream.Send(&api.ListBmpResponse{Station: rsp}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListBmp(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func (s *server) AddRpki(ctx context.Context, r *api.AddRpkiRequest) (*api.AddRpkiResponse, error) {
	return &api.AddRpkiResponse{}, s.bgpServer.AddRpki(ctx, r)
}

func (s *server) DeleteRpki(ctx context.Context, r *api.DeleteRpkiRequest) (*api.DeleteRpkiResponse, error) {
	return &api.DeleteRpkiResponse{}, s.bgpServer.DeleteRpki(ctx, r)
}

func (s *server) EnableRpki(ctx context.Context, r *api.EnableRpkiRequest) (*api.EnableRpkiResponse, error) {
	return &api.EnableRpkiResponse{}, s.bgpServer.EnableRpki(ctx, r)
}

func (s *server) DisableRpki(ctx context.Context, r *api.DisableRpkiRequest) (*api.DisableRpkiResponse, error) {
	return &api.DisableRpkiResponse{}, s.bgpServer.DisableRpki(ctx, r)
}

func (s *server) ResetRpki(ctx context.Context, r *api.ResetRpkiRequest) (*api.ResetRpkiResponse, error) {
	return &api.ResetRpkiResponse{}, s.bgpServer.ResetRpki(ctx, r)
}

func (s *server) ListRpki(r *api.ListRpkiRequest, stream api.GoBgpService_ListRpkiServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(r *api.Rpki) {
		if sendErr = stream.Send(&api.ListRpkiResponse{Server: r}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListRpki(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func (s *server) ListRpkiTable(r *api.ListRpkiTableRequest, stream api.GoBgpService_ListRpkiTableServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(r *api.Roa) {
		if sendErr = stream.Send(&api.ListRpkiTableResponse{Roa: r}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListRpkiTable(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func (s *server) EnableZebra(ctx context.Context, r *api.EnableZebraRequest) (*api.EnableZebraResponse, error) {
	return &api.EnableZebraResponse{}, s.bgpServer.EnableZebra(ctx, r)
}

func (s *server) ListVrf(r *api.ListVrfRequest, stream api.GoBgpService_ListVrfServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(v *api.Vrf) {
		if sendErr = stream.Send(&api.ListVrfResponse{Vrf: v}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListVrf(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func (s *server) AddVrf(ctx context.Context, r *api.AddVrfRequest) (*api.AddVrfResponse, error) {
	return &api.AddVrfResponse{}, s.bgpServer.AddVrf(ctx, r)
}

func (s *server) DeleteVrf(ctx context.Context, r *api.DeleteVrfRequest) (*api.DeleteVrfResponse, error) {
	return &api.DeleteVrfResponse{}, s.bgpServer.DeleteVrf(ctx, r)
}

func readMpGracefulRestartFromAPIStruct(c *oc.MpGracefulRestart, a *api.MpGracefulRestart) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
	}
}

func readAfiSafiConfigFromAPIStruct(c *oc.AfiSafiConfig, a *api.AfiSafiConfig) {
	if c == nil || a == nil {
		return
	}
	rf := bgp.NewFamily(uint16(a.Family.Afi), uint8(a.Family.Safi))
	c.AfiSafiName = oc.AfiSafiType(rf.String())
	c.Enabled = a.Enabled
}

func readAfiSafiStateFromAPIStruct(s *oc.AfiSafiState, a *api.AfiSafiConfig) {
	if s == nil || a == nil {
		return
	}
	// Store only address family value for the convenience
	s.Family = bgp.NewFamily(uint16(a.Family.Afi), uint8(a.Family.Safi))
}

func readPrefixLimitFromAPIStruct(c *oc.PrefixLimit, a *api.PrefixLimit) {
	if c == nil || a == nil {
		return
	}
	c.Config.MaxPrefixes = a.MaxPrefixes
	c.Config.ShutdownThresholdPct = oc.Percentage(a.ShutdownThresholdPct)
}

func readApplyPolicyFromAPIStruct(c *oc.ApplyPolicy, a *api.ApplyPolicy) {
	if c == nil || a == nil {
		return
	}
	f := func(a api.RouteAction) oc.DefaultPolicyType {
		switch a {
		case api.RouteAction_ROUTE_ACTION_ACCEPT:
			return oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
		case api.RouteAction_ROUTE_ACTION_REJECT:
			return oc.DEFAULT_POLICY_TYPE_REJECT_ROUTE
		}
		return ""
	}

	if a.ImportPolicy != nil {
		c.Config.DefaultImportPolicy = f(a.ImportPolicy.DefaultAction)
		for _, p := range a.ImportPolicy.Policies {
			c.Config.ImportPolicyList = append(c.Config.ImportPolicyList, p.Name)
		}
	}
	if a.ExportPolicy != nil {
		c.Config.DefaultExportPolicy = f(a.ExportPolicy.DefaultAction)
		for _, p := range a.ExportPolicy.Policies {
			c.Config.ExportPolicyList = append(c.Config.ExportPolicyList, p.Name)
		}
	}
}

func readRouteSelectionOptionsFromAPIStruct(c *oc.RouteSelectionOptions, a *api.RouteSelectionOptions) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.AlwaysCompareMed = a.Config.AlwaysCompareMed
		c.Config.IgnoreAsPathLength = a.Config.IgnoreAsPathLength
		c.Config.ExternalCompareRouterId = a.Config.ExternalCompareRouterId
		c.Config.AdvertiseInactiveRoutes = a.Config.AdvertiseInactiveRoutes
		c.Config.EnableAigp = a.Config.EnableAigp
		c.Config.IgnoreNextHopIgpMetric = a.Config.IgnoreNextHopIgpMetric
	}
}

func readUseMultiplePathsFromAPIStruct(c *oc.UseMultiplePaths, a *api.UseMultiplePaths) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
	}
	if a.Ebgp != nil && a.Ebgp.Config != nil {
		c.Ebgp = oc.Ebgp{
			Config: oc.EbgpConfig{
				AllowMultipleAs: a.Ebgp.Config.AllowMultipleAsn,
				MaximumPaths:    a.Ebgp.Config.MaximumPaths,
			},
		}
	}
	if a.Ibgp != nil && a.Ibgp.Config != nil {
		c.Ibgp = oc.Ibgp{
			Config: oc.IbgpConfig{
				MaximumPaths: a.Ibgp.Config.MaximumPaths,
			},
		}
	}
}

func readRouteTargetMembershipFromAPIStruct(c *oc.RouteTargetMembership, a *api.RouteTargetMembership) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.DeferralTime = uint16(a.Config.DeferralTime)
	}
}

func readLongLivedGracefulRestartFromAPIStruct(c *oc.LongLivedGracefulRestart, a *api.LongLivedGracefulRestart) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
		c.Config.RestartTime = a.Config.RestartTime
	}
}

func readAddPathsFromAPIStruct(c *oc.AddPaths, a *api.AddPaths) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Receive = a.Config.Receive
		c.Config.SendMax = uint8(a.Config.SendMax)
	}
}

func PeerTypeFromApi(a api.PeerType) (oc.PeerType, error) {
	switch a {
	case api.PeerType_PEER_TYPE_EXTERNAL:
		return oc.PEER_TYPE_EXTERNAL, nil
	default:
		// We should return an error but there are many code to use uninitialized PeerType..
		// api.PeerType_PEER_TYPE_INTERNAL:
		return oc.PEER_TYPE_INTERNAL, nil
	}
}

func newNeighborFromAPIStruct(a *api.Peer) (*oc.Neighbor, error) {
	pconf := &oc.Neighbor{}
	if a.Conf != nil {
		var err error
		pconf.Config.PeerAs = a.Conf.PeerAsn
		pconf.Config.LocalAs = a.Conf.LocalAsn
		pconf.Config.AuthPassword = a.Conf.AuthPassword
		pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
		pconf.Config.Description = a.Conf.Description
		pconf.Config.PeerGroup = a.Conf.PeerGroup
		pconf.Config.PeerType, err = PeerTypeFromApi(a.Conf.Type)
		if err != nil {
			return nil, err
		}
		if addr, err := netip.ParseAddr(a.Conf.NeighborAddress); err == nil {
			pconf.Config.NeighborAddress = addr
		}
		pconf.Config.AdminDown = a.Conf.AdminDown
		pconf.Config.NeighborInterface = a.Conf.NeighborInterface
		pconf.Config.Vrf = a.Conf.Vrf
		pconf.AsPathOptions.Config.AllowOwnAs = uint8(a.Conf.AllowOwnAsn)
		pconf.AsPathOptions.Config.ReplacePeerAs = a.Conf.ReplacePeerAsn
		pconf.AsPathOptions.Config.AllowAsPathLoopLocal = a.Conf.AllowAspathLoopLocal
		pconf.Config.SendSoftwareVersion = a.Conf.SendSoftwareVersion

		switch a.Conf.RemovePrivate {
		case api.RemovePrivate_REMOVE_PRIVATE_ALL:
			pconf.Config.RemovePrivateAs = oc.REMOVE_PRIVATE_AS_OPTION_ALL
		case api.RemovePrivate_REMOVE_PRIVATE_REPLACE:
			pconf.Config.RemovePrivateAs = oc.REMOVE_PRIVATE_AS_OPTION_REPLACE
		}

		if a.State != nil {
			localCaps, err := apiutil.UnmarshalCapabilities(a.State.LocalCap)
			if err != nil {
				return nil, err
			}
			remoteCaps, err := apiutil.UnmarshalCapabilities(a.State.RemoteCap)
			if err != nil {
				return nil, err
			}
			pconf.State.LocalCapabilityList = localCaps
			pconf.State.RemoteCapabilityList = remoteCaps

			if addr, err := netip.ParseAddr(a.State.RouterId); err == nil {
				pconf.State.RemoteRouterId = addr
			}
		}

		for _, af := range a.AfiSafis {
			afiSafi := oc.AfiSafi{}
			readMpGracefulRestartFromAPIStruct(&afiSafi.MpGracefulRestart, af.MpGracefulRestart)
			readAfiSafiConfigFromAPIStruct(&afiSafi.Config, af.Config)
			readAfiSafiStateFromAPIStruct(&afiSafi.State, af.Config)
			readApplyPolicyFromAPIStruct(&afiSafi.ApplyPolicy, af.ApplyPolicy)
			readRouteSelectionOptionsFromAPIStruct(&afiSafi.RouteSelectionOptions, af.RouteSelectionOptions)
			readUseMultiplePathsFromAPIStruct(&afiSafi.UseMultiplePaths, af.UseMultiplePaths)
			readPrefixLimitFromAPIStruct(&afiSafi.PrefixLimit, af.PrefixLimits)
			readRouteTargetMembershipFromAPIStruct(&afiSafi.RouteTargetMembership, af.RouteTargetMembership)
			readLongLivedGracefulRestartFromAPIStruct(&afiSafi.LongLivedGracefulRestart, af.LongLivedGracefulRestart)
			readAddPathsFromAPIStruct(&afiSafi.AddPaths, af.AddPaths)
			pconf.AfiSafis = append(pconf.AfiSafis, afiSafi)
		}
	}

	if a.Timers != nil {
		if a.Timers.Config != nil {
			pconf.Timers.Config.ConnectRetry = float64(a.Timers.Config.ConnectRetry)
			pconf.Timers.Config.HoldTime = float64(a.Timers.Config.HoldTime)
			pconf.Timers.Config.KeepaliveInterval = float64(a.Timers.Config.KeepaliveInterval)
			pconf.Timers.Config.MinimumAdvertisementInterval = float64(a.Timers.Config.MinimumAdvertisementInterval)
			pconf.Timers.Config.IdleHoldTimeAfterReset = float64(a.Timers.Config.IdleHoldTimeAfterReset)
		}
		if a.Timers.State != nil {
			pconf.Timers.State.KeepaliveInterval = float64(a.Timers.State.KeepaliveInterval)
			pconf.Timers.State.NegotiatedHoldTime = float64(a.Timers.State.NegotiatedHoldTime)
		}
	}
	if a.RouteReflector != nil {
		if id, err := netip.ParseAddr(a.RouteReflector.RouteReflectorClusterId); err == nil {
			pconf.RouteReflector.Config.RouteReflectorClusterId = id
		}
		pconf.RouteReflector.Config.RouteReflectorClient = a.RouteReflector.RouteReflectorClient
	}
	if a.RouteServer != nil {
		pconf.RouteServer.Config.RouteServerClient = a.RouteServer.RouteServerClient
		pconf.RouteServer.Config.SecondaryRoute = a.RouteServer.SecondaryRoute
	}
	if a.GracefulRestart != nil {
		pconf.GracefulRestart.Config.Enabled = a.GracefulRestart.Enabled
		pconf.GracefulRestart.Config.RestartTime = uint16(a.GracefulRestart.RestartTime)
		pconf.GracefulRestart.Config.HelperOnly = a.GracefulRestart.HelperOnly
		pconf.GracefulRestart.Config.DeferralTime = uint16(a.GracefulRestart.DeferralTime)
		pconf.GracefulRestart.Config.NotificationEnabled = a.GracefulRestart.NotificationEnabled
		pconf.GracefulRestart.Config.LongLivedEnabled = a.GracefulRestart.LonglivedEnabled
		pconf.GracefulRestart.State.LocalRestarting = a.GracefulRestart.LocalRestarting
	}
	readApplyPolicyFromAPIStruct(&pconf.ApplyPolicy, a.ApplyPolicy)
	if a.Transport != nil {
		if a.Transport.LocalAddress != "" {
			if addr, err := netip.ParseAddr(a.Transport.LocalAddress); err == nil {
				pconf.Transport.Config.LocalAddress = addr
			}
		}
		pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
		pconf.Transport.Config.RemotePort = uint16(a.Transport.RemotePort)
		pconf.Transport.Config.LocalPort = uint16(a.Transport.LocalPort)
		pconf.Transport.Config.BindInterface = a.Transport.BindInterface
		pconf.Transport.Config.TcpMss = uint16(a.Transport.TcpMss)
		pconf.Transport.Config.IpTos = uint8(a.Transport.IpTos)
	}
	if a.EbgpMultihop != nil {
		pconf.EbgpMultihop.Config.Enabled = a.EbgpMultihop.Enabled
		pconf.EbgpMultihop.Config.MultihopTtl = uint8(a.EbgpMultihop.MultihopTtl)
	}
	if a.TtlSecurity != nil {
		pconf.TtlSecurity.Config.Enabled = a.TtlSecurity.Enabled
		pconf.TtlSecurity.Config.TtlMin = uint8(a.TtlSecurity.TtlMin)
	}
	if a.State != nil {
		var sessionState oc.SessionState
		switch a.State.SessionState {
		case api.PeerState_SESSION_STATE_UNSPECIFIED:
			sessionState = oc.SESSION_STATE_IDLE
		case api.PeerState_SESSION_STATE_IDLE:
			sessionState = oc.SESSION_STATE_IDLE
		case api.PeerState_SESSION_STATE_CONNECT:
			sessionState = oc.SESSION_STATE_CONNECT
		case api.PeerState_SESSION_STATE_ACTIVE:
			sessionState = oc.SESSION_STATE_ACTIVE
		case api.PeerState_SESSION_STATE_OPENSENT:
			sessionState = oc.SESSION_STATE_OPENSENT
		case api.PeerState_SESSION_STATE_OPENCONFIRM:
			sessionState = oc.SESSION_STATE_OPENCONFIRM
		case api.PeerState_SESSION_STATE_ESTABLISHED:
			sessionState = oc.SESSION_STATE_ESTABLISHED
		default:
			sessionState = oc.SESSION_STATE_IDLE
		}
		pconf.State.SessionState = sessionState
		pconf.State.AdminState = oc.IntToAdminStateMap[int(a.State.AdminState)]

		pconf.State.PeerAs = a.State.PeerAsn
		var err error
		pconf.State.PeerType, err = PeerTypeFromApi(a.State.Type)
		if err != nil {
			return nil, err
		}
		if addr, err := netip.ParseAddr(a.State.NeighborAddress); err == nil {
			pconf.State.NeighborAddress = addr
		}
		if a.State.Messages != nil {
			if a.State.Messages.Sent != nil {
				pconf.State.Messages.Sent.Update = a.State.Messages.Sent.Update
				pconf.State.Messages.Sent.Notification = a.State.Messages.Sent.Notification
				pconf.State.Messages.Sent.Open = a.State.Messages.Sent.Open
				pconf.State.Messages.Sent.Refresh = a.State.Messages.Sent.Refresh
				pconf.State.Messages.Sent.Keepalive = a.State.Messages.Sent.Keepalive
				pconf.State.Messages.Sent.Discarded = a.State.Messages.Sent.Discarded
				pconf.State.Messages.Sent.Total = a.State.Messages.Sent.Total
			}
			if a.State.Messages.Received != nil {
				pconf.State.Messages.Received.Update = a.State.Messages.Received.Update
				pconf.State.Messages.Received.Open = a.State.Messages.Received.Open
				pconf.State.Messages.Received.Refresh = a.State.Messages.Received.Refresh
				pconf.State.Messages.Received.Keepalive = a.State.Messages.Received.Keepalive
				pconf.State.Messages.Received.Discarded = a.State.Messages.Received.Discarded
				pconf.State.Messages.Received.Total = a.State.Messages.Received.Total
			}
		}
	}
	return pconf, nil
}

func newPeerGroupFromAPIStruct(a *api.PeerGroup) (*oc.PeerGroup, error) {
	pconf := &oc.PeerGroup{}
	if a.Conf != nil {
		pconf.Config.PeerAs = a.Conf.PeerAsn
		pconf.Config.LocalAs = a.Conf.LocalAsn
		pconf.Config.AuthPassword = a.Conf.AuthPassword
		pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
		pconf.Config.Description = a.Conf.Description
		pconf.Config.PeerGroupName = a.Conf.PeerGroupName
		pconf.Config.SendSoftwareVersion = a.Conf.SendSoftwareVersion

		switch a.Conf.RemovePrivate {
		case api.RemovePrivate_REMOVE_PRIVATE_ALL:
			pconf.Config.RemovePrivateAs = oc.REMOVE_PRIVATE_AS_OPTION_ALL
		case api.RemovePrivate_REMOVE_PRIVATE_REPLACE:
			pconf.Config.RemovePrivateAs = oc.REMOVE_PRIVATE_AS_OPTION_REPLACE
		}

		for _, af := range a.AfiSafis {
			afiSafi := oc.AfiSafi{}
			readMpGracefulRestartFromAPIStruct(&afiSafi.MpGracefulRestart, af.MpGracefulRestart)
			readAfiSafiConfigFromAPIStruct(&afiSafi.Config, af.Config)
			readAfiSafiStateFromAPIStruct(&afiSafi.State, af.Config)
			readApplyPolicyFromAPIStruct(&afiSafi.ApplyPolicy, af.ApplyPolicy)
			readRouteSelectionOptionsFromAPIStruct(&afiSafi.RouteSelectionOptions, af.RouteSelectionOptions)
			readUseMultiplePathsFromAPIStruct(&afiSafi.UseMultiplePaths, af.UseMultiplePaths)
			readPrefixLimitFromAPIStruct(&afiSafi.PrefixLimit, af.PrefixLimits)
			readRouteTargetMembershipFromAPIStruct(&afiSafi.RouteTargetMembership, af.RouteTargetMembership)
			readLongLivedGracefulRestartFromAPIStruct(&afiSafi.LongLivedGracefulRestart, af.LongLivedGracefulRestart)
			readAddPathsFromAPIStruct(&afiSafi.AddPaths, af.AddPaths)
			pconf.AfiSafis = append(pconf.AfiSafis, afiSafi)
		}
	}

	if a.Timers != nil {
		if a.Timers.Config != nil {
			pconf.Timers.Config.ConnectRetry = float64(a.Timers.Config.ConnectRetry)
			pconf.Timers.Config.HoldTime = float64(a.Timers.Config.HoldTime)
			pconf.Timers.Config.KeepaliveInterval = float64(a.Timers.Config.KeepaliveInterval)
			pconf.Timers.Config.MinimumAdvertisementInterval = float64(a.Timers.Config.MinimumAdvertisementInterval)
			pconf.Timers.Config.IdleHoldTimeAfterReset = float64(a.Timers.Config.IdleHoldTimeAfterReset)
		}
		if a.Timers.State != nil {
			pconf.Timers.State.KeepaliveInterval = float64(a.Timers.State.KeepaliveInterval)
			pconf.Timers.State.NegotiatedHoldTime = float64(a.Timers.State.NegotiatedHoldTime)
		}
	}
	if a.RouteReflector != nil {
		if id, err := netip.ParseAddr(a.RouteReflector.RouteReflectorClusterId); err == nil {
			pconf.RouteReflector.Config.RouteReflectorClusterId = id
		}
		pconf.RouteReflector.Config.RouteReflectorClient = a.RouteReflector.RouteReflectorClient
	}
	if a.RouteServer != nil {
		pconf.RouteServer.Config.RouteServerClient = a.RouteServer.RouteServerClient
		pconf.RouteServer.Config.SecondaryRoute = a.RouteServer.SecondaryRoute
	}
	if a.GracefulRestart != nil {
		pconf.GracefulRestart.Config.Enabled = a.GracefulRestart.Enabled
		pconf.GracefulRestart.Config.RestartTime = uint16(a.GracefulRestart.RestartTime)
		pconf.GracefulRestart.Config.HelperOnly = a.GracefulRestart.HelperOnly
		pconf.GracefulRestart.Config.DeferralTime = uint16(a.GracefulRestart.DeferralTime)
		pconf.GracefulRestart.Config.NotificationEnabled = a.GracefulRestart.NotificationEnabled
		pconf.GracefulRestart.Config.LongLivedEnabled = a.GracefulRestart.LonglivedEnabled
		pconf.GracefulRestart.State.LocalRestarting = a.GracefulRestart.LocalRestarting
	}
	readApplyPolicyFromAPIStruct(&pconf.ApplyPolicy, a.ApplyPolicy)
	if a.Transport != nil {
		if a.Transport.LocalAddress != "" {
			if addr, err := netip.ParseAddr(a.Transport.LocalAddress); err == nil {
				pconf.Transport.Config.LocalAddress = addr
			}
		}
		pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
		pconf.Transport.Config.RemotePort = uint16(a.Transport.RemotePort)
		pconf.Transport.Config.TcpMss = uint16(a.Transport.TcpMss)
		pconf.Transport.Config.IpTos = uint8(a.Transport.IpTos)
	}
	if a.EbgpMultihop != nil {
		pconf.EbgpMultihop.Config.Enabled = a.EbgpMultihop.Enabled
		pconf.EbgpMultihop.Config.MultihopTtl = uint8(a.EbgpMultihop.MultihopTtl)
	}
	if a.TtlSecurity != nil {
		pconf.TtlSecurity.Config.Enabled = a.TtlSecurity.Enabled
		pconf.TtlSecurity.Config.TtlMin = uint8(a.TtlSecurity.TtlMin)
	}
	if a.Info != nil {
		pconf.State.TotalPaths = a.Info.TotalPaths
		pconf.State.TotalPrefixes = a.Info.TotalPrefixes
		pconf.State.PeerAs = a.Info.PeerAsn
		var err error
		pconf.State.PeerType, err = PeerTypeFromApi(a.Info.Type)
		if err != nil {
			return nil, err
		}
	}
	return pconf, nil
}

func (s *server) AddPeer(ctx context.Context, r *api.AddPeerRequest) (*api.AddPeerResponse, error) {
	return &api.AddPeerResponse{}, s.bgpServer.AddPeer(ctx, r)
}

func (s *server) DeletePeer(ctx context.Context, r *api.DeletePeerRequest) (*api.DeletePeerResponse, error) {
	return &api.DeletePeerResponse{}, s.bgpServer.DeletePeer(ctx, r)
}

func (s *server) UpdatePeer(ctx context.Context, r *api.UpdatePeerRequest) (*api.UpdatePeerResponse, error) {
	return s.bgpServer.UpdatePeer(ctx, r)
}

func (s *server) AddPeerGroup(ctx context.Context, r *api.AddPeerGroupRequest) (*api.AddPeerGroupResponse, error) {
	return &api.AddPeerGroupResponse{}, s.bgpServer.AddPeerGroup(ctx, r)
}

func (s *server) DeletePeerGroup(ctx context.Context, r *api.DeletePeerGroupRequest) (*api.DeletePeerGroupResponse, error) {
	return &api.DeletePeerGroupResponse{}, s.bgpServer.DeletePeerGroup(ctx, r)
}

func (s *server) UpdatePeerGroup(ctx context.Context, r *api.UpdatePeerGroupRequest) (*api.UpdatePeerGroupResponse, error) {
	return s.bgpServer.UpdatePeerGroup(ctx, r)
}

func (s *server) AddDynamicNeighbor(ctx context.Context, r *api.AddDynamicNeighborRequest) (*api.AddDynamicNeighborResponse, error) {
	return &api.AddDynamicNeighborResponse{}, s.bgpServer.AddDynamicNeighbor(ctx, r)
}

func (s *server) DeleteDynamicNeighbor(ctx context.Context, r *api.DeleteDynamicNeighborRequest) (*api.DeleteDynamicNeighborResponse, error) {
	return &api.DeleteDynamicNeighborResponse{}, s.bgpServer.DeleteDynamicNeighbor(ctx, r)
}

func newPrefixFromApiStruct(a *api.Prefix) (*table.Prefix, error) {
	prefix, err := netip.ParsePrefix(a.IpPrefix)
	if err != nil {
		return nil, err
	}
	rf := bgp.RF_IPv4_UC
	if prefix.Addr().Is6() {
		rf = bgp.RF_IPv6_UC
	}
	return &table.Prefix{
		Prefix:             prefix,
		AddressFamily:      rf,
		MasklengthRangeMin: uint8(a.MaskLengthMin),
		MasklengthRangeMax: uint8(a.MaskLengthMax),
	}, nil
}

func newConfigPrefixFromAPIStruct(a *api.Prefix) (*oc.Prefix, error) {
	_, prefix, err := net.ParseCIDR(a.IpPrefix)
	if err != nil {
		return nil, err
	}
	return &oc.Prefix{
		IpPrefix:        netip.MustParsePrefix(prefix.String()),
		MasklengthRange: fmt.Sprintf("%d..%d", a.MaskLengthMin, a.MaskLengthMax),
	}, nil
}

func newConfigDefinedSetsFromApiStruct(a []*api.DefinedSet) (*oc.DefinedSets, error) {
	ps := make([]oc.PrefixSet, 0)
	ns := make([]oc.NeighborSet, 0)
	as := make([]oc.AsPathSet, 0)
	cs := make([]oc.CommunitySet, 0)
	es := make([]oc.ExtCommunitySet, 0)
	ls := make([]oc.LargeCommunitySet, 0)

	for _, ds := range a {
		if ds.Name == "" {
			return nil, fmt.Errorf("empty neighbor set name")
		}
		switch ds.DefinedType {
		case api.DefinedType_DEFINED_TYPE_PREFIX:
			prefixes := make([]oc.Prefix, 0, len(ds.Prefixes))
			for _, p := range ds.Prefixes {
				prefix, err := newConfigPrefixFromAPIStruct(p)
				if err != nil {
					return nil, err
				}
				prefixes = append(prefixes, *prefix)
			}
			ps = append(ps, oc.PrefixSet{
				PrefixSetName: ds.Name,
				PrefixList:    prefixes,
			})
		case api.DefinedType_DEFINED_TYPE_NEIGHBOR:
			ns = append(ns, oc.NeighborSet{
				NeighborSetName:  ds.Name,
				NeighborInfoList: ds.List,
			})
		case api.DefinedType_DEFINED_TYPE_AS_PATH:
			as = append(as, oc.AsPathSet{
				AsPathSetName: ds.Name,
				AsPathList:    ds.List,
			})
		case api.DefinedType_DEFINED_TYPE_COMMUNITY:
			cs = append(cs, oc.CommunitySet{
				CommunitySetName: ds.Name,
				CommunityList:    ds.List,
			})
		case api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY:
			es = append(es, oc.ExtCommunitySet{
				ExtCommunitySetName: ds.Name,
				ExtCommunityList:    ds.List,
			})
		case api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY:
			ls = append(ls, oc.LargeCommunitySet{
				LargeCommunitySetName: ds.Name,
				LargeCommunityList:    ds.List,
			})
		default:
			return nil, status.Errorf(codes.InvalidArgument, "unknown defined set type: %s", ds.DefinedType)
		}
	}

	return &oc.DefinedSets{
		PrefixSets:   ps,
		NeighborSets: ns,
		BgpDefinedSets: oc.BgpDefinedSets{
			AsPathSets:         as,
			CommunitySets:      cs,
			ExtCommunitySets:   es,
			LargeCommunitySets: ls,
		},
	}, nil
}

func newDefinedSetFromApiStruct(a *api.DefinedSet) (table.DefinedSet, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty neighbor set name")
	}
	switch a.DefinedType {
	case api.DefinedType_DEFINED_TYPE_PREFIX:
		prefixes := make([]*table.Prefix, 0, len(a.Prefixes))
		for _, p := range a.Prefixes {
			prefix, err := newPrefixFromApiStruct(p)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix)
		}
		return table.NewPrefixSetFromApiStruct(a.Name, prefixes)
	case api.DefinedType_DEFINED_TYPE_NEIGHBOR:
		list := make([]net.IPNet, 0, len(a.List))
		for _, x := range a.List {
			_, addr, err := net.ParseCIDR(x)
			if err != nil {
				return nil, fmt.Errorf("invalid address or prefix: %s", x)
			}
			list = append(list, *addr)
		}
		return table.NewNeighborSetFromApiStruct(a.Name, list)
	case api.DefinedType_DEFINED_TYPE_AS_PATH:
		return table.NewAsPathSet(oc.AsPathSet{
			AsPathSetName: a.Name,
			AsPathList:    a.List,
		})
	case api.DefinedType_DEFINED_TYPE_COMMUNITY:
		return table.NewCommunitySet(oc.CommunitySet{
			CommunitySetName: a.Name,
			CommunityList:    a.List,
		})
	case api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY:
		return table.NewExtCommunitySet(oc.ExtCommunitySet{
			ExtCommunitySetName: a.Name,
			ExtCommunityList:    a.List,
		})
	case api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY:
		return table.NewLargeCommunitySet(oc.LargeCommunitySet{
			LargeCommunitySetName: a.Name,
			LargeCommunityList:    a.List,
		})
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown defined set type: %s", a.DefinedType)
	}
}

var _regexpPrefixMaskLengthRange = regexp.MustCompile(`(\d+)\.\.(\d+)`)

func (s *server) ListDefinedSet(r *api.ListDefinedSetRequest, stream api.GoBgpService_ListDefinedSetServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(d *api.DefinedSet) {
		if sendErr = stream.Send(&api.ListDefinedSetResponse{DefinedSet: d}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListDefinedSet(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func (s *server) AddDefinedSet(ctx context.Context, r *api.AddDefinedSetRequest) (*api.AddDefinedSetResponse, error) {
	return &api.AddDefinedSetResponse{}, s.bgpServer.AddDefinedSet(ctx, r)
}

func (s *server) DeleteDefinedSet(ctx context.Context, r *api.DeleteDefinedSetRequest) (*api.DeleteDefinedSetResponse, error) {
	return &api.DeleteDefinedSetResponse{}, s.bgpServer.DeleteDefinedSet(ctx, r)
}

var _regexpMedActionType = regexp.MustCompile(`([+-]?)(\d+)`)

func toOcAttributeComparison(a api.Comparison) oc.AttributeComparison {
	switch a {
	case api.Comparison_COMPARISON_EQ:
		return oc.ATTRIBUTE_COMPARISON_EQ
	case api.Comparison_COMPARISON_GE:
		return oc.ATTRIBUTE_COMPARISON_GE
	case api.Comparison_COMPARISON_LE:
		return oc.ATTRIBUTE_COMPARISON_LE
	default:
		return oc.ATTRIBUTE_COMPARISON_EQ
	}
}

func matchSetOptionsRestrictedTypeToAPI(t oc.MatchSetOptionsRestrictedType) api.MatchSet_Type {
	t = t.DefaultAsNeeded()
	switch t {
	case oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY:
		return api.MatchSet_TYPE_ANY
	case oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT:
		return api.MatchSet_TYPE_INVERT
	}
	return api.MatchSet_TYPE_ANY
}

func toStatementApi(s *oc.Statement) *api.Statement {
	cs := &api.Conditions{}
	if s.Conditions.MatchPrefixSet.PrefixSet != "" {
		cs.PrefixSet = &api.MatchSet{
			Type: matchSetOptionsRestrictedTypeToAPI(s.Conditions.MatchPrefixSet.MatchSetOptions),
			Name: s.Conditions.MatchPrefixSet.PrefixSet,
		}
	}
	if s.Conditions.MatchNeighborSet.NeighborSet != "" {
		cs.NeighborSet = &api.MatchSet{
			Type: matchSetOptionsRestrictedTypeToAPI(s.Conditions.MatchNeighborSet.MatchSetOptions),
			Name: s.Conditions.MatchNeighborSet.NeighborSet,
		}
	}
	if s.Conditions.BgpConditions.CommunityCount.Operator != "" {
		cs.CommunityCount = &api.CommunityCount{
			Count: s.Conditions.BgpConditions.CommunityCount.Value,
			Type:  table.ToComparisonApi(s.Conditions.BgpConditions.CommunityCount.Operator),
		}
	}
	if s.Conditions.BgpConditions.AsPathLength.Operator != "" {
		cs.AsPathLength = &api.AsPathLength{
			Length: s.Conditions.BgpConditions.AsPathLength.Value,
			Type:   table.ToComparisonApi(s.Conditions.BgpConditions.AsPathLength.Operator),
		}
	}
	if s.Conditions.BgpConditions.LocalPrefEq != 0 {
		cs.LocalPrefEq = &api.LocalPrefEq{Value: s.Conditions.BgpConditions.LocalPrefEq}
	}
	if s.Conditions.BgpConditions.MedEq != 0 {
		cs.MedEq = &api.MedEq{Value: s.Conditions.BgpConditions.MedEq}
	}
	if s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet != "" {
		o, _ := table.NewMatchOption(s.Conditions.BgpConditions.MatchAsPathSet.MatchSetOptions)
		cs.AsPathSet = &api.MatchSet{
			Type: o.ToApi(),
			Name: s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet,
		}
	}
	if s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet != "" {
		o, _ := table.NewMatchOption(s.Conditions.BgpConditions.MatchCommunitySet.MatchSetOptions)
		cs.CommunitySet = &api.MatchSet{
			Type: o.ToApi(),
			Name: s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet != "" {
		o, _ := table.NewMatchOption(s.Conditions.BgpConditions.MatchExtCommunitySet.MatchSetOptions)
		cs.ExtCommunitySet = &api.MatchSet{
			Type: o.ToApi(),
			Name: s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet != "" {
		o, _ := table.NewMatchOption(s.Conditions.BgpConditions.MatchLargeCommunitySet.MatchSetOptions)
		cs.LargeCommunitySet = &api.MatchSet{
			Type: o.ToApi(),
			Name: s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.RouteType != "" {
		cs.RouteType = api.Conditions_RouteType(s.Conditions.BgpConditions.RouteType.ToInt())
	}
	if len(s.Conditions.BgpConditions.NextHopInList) > 0 {
		l := make([]string, 0, len(s.Conditions.BgpConditions.NextHopInList))
		for _, nh := range s.Conditions.BgpConditions.NextHopInList {
			l = append(l, nh.String())
		}
		cs.NextHopInList = l
	}
	if s.Conditions.BgpConditions.AfiSafiInList != nil {
		afiSafiIn := make([]*api.Family, 0)
		for _, afiSafiType := range s.Conditions.BgpConditions.AfiSafiInList {
			if mapped, ok := bgp.AddressFamilyValueMap[string(afiSafiType)]; ok {
				afiSafiIn = append(afiSafiIn, &api.Family{Afi: api.Family_Afi(mapped.Afi()), Safi: api.Family_Safi(mapped.Safi())})
			}
		}
		cs.AfiSafiIn = afiSafiIn
	}
	switch s.Conditions.BgpConditions.RpkiValidationResult {
	case oc.RPKI_VALIDATION_RESULT_TYPE_NONE:
		cs.RpkiResult = api.ValidationState_VALIDATION_STATE_NONE
	case oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND:
		cs.RpkiResult = api.ValidationState_VALIDATION_STATE_NOT_FOUND
	case oc.RPKI_VALIDATION_RESULT_TYPE_VALID:
		cs.RpkiResult = api.ValidationState_VALIDATION_STATE_VALID
	case oc.RPKI_VALIDATION_RESULT_TYPE_INVALID:
		cs.RpkiResult = api.ValidationState_VALIDATION_STATE_INVALID
	default:
		cs.RpkiResult = api.ValidationState_VALIDATION_STATE_UNSPECIFIED
	}

	as := &api.Actions{
		RouteAction: func() api.RouteAction {
			switch s.Actions.RouteDisposition {
			case oc.ROUTE_DISPOSITION_ACCEPT_ROUTE:
				return api.RouteAction_ROUTE_ACTION_ACCEPT
			case oc.ROUTE_DISPOSITION_REJECT_ROUTE:
				return api.RouteAction_ROUTE_ACTION_REJECT
			}
			return api.RouteAction_ROUTE_ACTION_UNSPECIFIED
		}(),
		Community: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			action := api.CommunityAction_TYPE_UNSPECIFIED
			switch oc.BgpSetCommunityOptionType(s.Actions.BgpActions.SetCommunity.Options) {
			case oc.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
				action = api.CommunityAction_TYPE_ADD
			case oc.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
				action = api.CommunityAction_TYPE_REMOVE
			case oc.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
				action = api.CommunityAction_TYPE_REPLACE
			}
			return &api.CommunityAction{
				Type:        action,
				Communities: s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList,
			}
		}(),
		Med: func() *api.MedAction {
			medStr := strings.TrimSpace(string(s.Actions.BgpActions.SetMed))
			if len(medStr) == 0 {
				return nil
			}
			matches := _regexpMedActionType.FindStringSubmatch(medStr)
			if len(matches) == 0 {
				return nil
			}
			action := api.MedAction_TYPE_REPLACE
			switch matches[1] {
			case "+", "-":
				action = api.MedAction_TYPE_MOD
			}
			value, err := strconv.ParseInt(matches[1]+matches[2], 10, 64)
			if err != nil {
				return nil
			}
			return &api.MedAction{
				Value: value,
				Type:  action,
			}
		}(),
		AsPrepend: func() *api.AsPrependAction {
			if len(s.Actions.BgpActions.SetAsPathPrepend.As) == 0 {
				return nil
			}
			var asn uint64
			useleft := false
			if s.Actions.BgpActions.SetAsPathPrepend.As != "last-as" {
				asn, _ = strconv.ParseUint(s.Actions.BgpActions.SetAsPathPrepend.As, 10, 32)
			} else {
				useleft = true
			}
			return &api.AsPrependAction{
				Asn:         uint32(asn),
				Repeat:      uint32(s.Actions.BgpActions.SetAsPathPrepend.RepeatN),
				UseLeftMost: useleft,
			}
		}(),
		ExtCommunity: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityAction_Type(oc.BgpSetCommunityOptionTypeToIntMap[oc.BgpSetCommunityOptionType(s.Actions.BgpActions.SetExtCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList,
			}
		}(),
		LargeCommunity: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityAction_Type(oc.BgpSetCommunityOptionTypeToIntMap[s.Actions.BgpActions.SetLargeCommunity.Options]),
				Communities: s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList,
			}
		}(),
		Nexthop: func() *api.NexthopAction {
			if len(string(s.Actions.BgpActions.SetNextHop)) == 0 {
				return nil
			}

			switch string(s.Actions.BgpActions.SetNextHop) {
			case "self":
				return &api.NexthopAction{
					Self: true,
				}
			case "unchanged":
				return &api.NexthopAction{
					Unchanged: true,
				}
			case "peer-address":
				return &api.NexthopAction{
					PeerAddress: true,
				}
			}
			return &api.NexthopAction{
				Address: string(s.Actions.BgpActions.SetNextHop),
			}
		}(),
		LocalPref: func() *api.LocalPrefAction {
			if s.Actions.BgpActions.SetLocalPref == 0 {
				return nil
			}
			return &api.LocalPrefAction{Value: s.Actions.BgpActions.SetLocalPref}
		}(),
		OriginAction: func() *api.OriginAction {
			if s.Actions.BgpActions.SetRouteOrigin.ToInt() == -1 {
				return nil
			}
			var apiOrigin api.OriginType
			switch s.Actions.BgpActions.SetRouteOrigin {
			case oc.BGP_ORIGIN_ATTR_TYPE_IGP:
				apiOrigin = api.OriginType_ORIGIN_TYPE_IGP
			case oc.BGP_ORIGIN_ATTR_TYPE_EGP:
				apiOrigin = api.OriginType_ORIGIN_TYPE_EGP
			case oc.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE:
				apiOrigin = api.OriginType_ORIGIN_TYPE_INCOMPLETE
			default:
				return nil
			}
			return &api.OriginAction{Origin: apiOrigin}
		}(),
	}
	return &api.Statement{
		Name:       s.Name,
		Conditions: cs,
		Actions:    as,
	}
}

func toConfigMatchSetOption(a api.MatchSet_Type) (oc.MatchSetOptionsType, error) {
	var typ oc.MatchSetOptionsType
	switch a {
	case api.MatchSet_TYPE_ANY:
		typ = oc.MATCH_SET_OPTIONS_TYPE_ANY
	case api.MatchSet_TYPE_ALL:
		typ = oc.MATCH_SET_OPTIONS_TYPE_ALL
	case api.MatchSet_TYPE_INVERT:
		typ = oc.MATCH_SET_OPTIONS_TYPE_INVERT
	default:
		return typ, status.Errorf(codes.InvalidArgument, "invalid match type %d", a)
	}
	return typ, nil
}

func toConfigMatchSetOptionRestricted(a api.MatchSet_Type) (oc.MatchSetOptionsRestrictedType, error) {
	var typ oc.MatchSetOptionsRestrictedType
	switch a {
	case api.MatchSet_TYPE_ANY:
		typ = oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	case api.MatchSet_TYPE_INVERT:
		typ = oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
	default:
		return typ, status.Errorf(codes.InvalidArgument, "invalid match restricted type %d", a)
	}
	return typ, nil
}

func newPrefixConditionFromApiStruct(a *api.MatchSet) (*table.PrefixCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOptionRestricted(a.Type)
	if err != nil {
		return nil, err
	}
	c := oc.MatchPrefixSet{
		PrefixSet:       a.Name,
		MatchSetOptions: typ,
	}
	return table.NewPrefixCondition(c)
}

func newNeighborConditionFromApiStruct(a *api.MatchSet) (*table.NeighborCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOptionRestricted(a.Type)
	if err != nil {
		return nil, err
	}
	c := oc.MatchNeighborSet{
		NeighborSet:     a.Name,
		MatchSetOptions: typ,
	}
	return table.NewNeighborCondition(c)
}

func newCommunityCountConditionFromApiStruct(a *api.CommunityCount) (*table.CommunityCountCondition, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewCommunityCountCondition(oc.CommunityCount{
		Operator: toOcAttributeComparison(a.Type),
		Value:    a.Count,
	})
}

func newAsPathLengthConditionFromApiStruct(a *api.AsPathLength) (*table.AsPathLengthCondition, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewAsPathLengthCondition(oc.AsPathLength{
		Operator: toOcAttributeComparison(a.Type),
		Value:    a.Length,
	})
}

func newLocalPrefEqConditionFromApiStruct(a *api.LocalPrefEq) (*table.LocalPreqEqCondition, error) {
	if a == nil || a.Value == 0 {
		return nil, nil
	}
	return table.NewLocalPrefEqCondition(a.Value)
}

func newMedEqConditionFromApiStruct(a *api.MedEq) (*table.MedEqCondition, error) {
	if a == nil || a.Value == 0 {
		return nil, nil
	}
	return table.NewMedEqCondition(a.Value)
}

func newAsPathConditionFromApiStruct(a *api.MatchSet) (*table.AsPathCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := oc.MatchAsPathSet{
		AsPathSet:       a.Name,
		MatchSetOptions: typ,
	}
	return table.NewAsPathCondition(c)
}

func newRpkiValidationConditionFromApiStruct(a api.ValidationState) (*table.RpkiValidationCondition, error) {
	c := oc.RpkiValidationResultType("")
	switch a {
	case api.ValidationState_VALIDATION_STATE_NONE:
		c = oc.RPKI_VALIDATION_RESULT_TYPE_NONE
	case api.ValidationState_VALIDATION_STATE_NOT_FOUND:
		c = oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
	case api.ValidationState_VALIDATION_STATE_VALID:
		c = oc.RPKI_VALIDATION_RESULT_TYPE_VALID
	case api.ValidationState_VALIDATION_STATE_INVALID:
		c = oc.RPKI_VALIDATION_RESULT_TYPE_INVALID
	default:
		return nil, nil
	}

	return table.NewRpkiValidationCondition(c)
}

func newRouteTypeConditionFromApiStruct(a api.Conditions_RouteType) (*table.RouteTypeCondition, error) {
	if a == 0 {
		return nil, nil
	}
	typ, ok := oc.IntToRouteTypeMap[int(a)]
	if !ok {
		return nil, fmt.Errorf("invalid route type: %d", a)
	}
	return table.NewRouteTypeCondition(typ)
}

func newOriginConditionFromApiStruct(apiOrigin api.OriginType) (*table.OriginCondition, error) {
	var origin oc.BgpOriginAttrType
	switch apiOrigin {
	case api.OriginType_ORIGIN_TYPE_UNSPECIFIED:
		return nil, nil
	case api.OriginType_ORIGIN_TYPE_IGP:
		origin = oc.BGP_ORIGIN_ATTR_TYPE_IGP
	case api.OriginType_ORIGIN_TYPE_EGP:
		origin = oc.BGP_ORIGIN_ATTR_TYPE_EGP
	case api.OriginType_ORIGIN_TYPE_INCOMPLETE:
		origin = oc.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unrecognized route origin type: %v", apiOrigin)
	}
	return table.NewOriginCondition(origin)
}

func newCommunityConditionFromApiStruct(a *api.MatchSet) (*table.CommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := oc.MatchCommunitySet{
		CommunitySet:    a.Name,
		MatchSetOptions: typ,
	}
	return table.NewCommunityCondition(c)
}

func newExtCommunityConditionFromApiStruct(a *api.MatchSet) (*table.ExtCommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := oc.MatchExtCommunitySet{
		ExtCommunitySet: a.Name,
		MatchSetOptions: typ,
	}
	return table.NewExtCommunityCondition(c)
}

func newLargeCommunityConditionFromApiStruct(a *api.MatchSet) (*table.LargeCommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := oc.MatchLargeCommunitySet{
		LargeCommunitySet: a.Name,
		MatchSetOptions:   typ,
	}
	return table.NewLargeCommunityCondition(c)
}

func newNextHopConditionFromApiStruct(a []string) (*table.NextHopCondition, error) {
	if a == nil {
		return nil, nil
	}

	return table.NewNextHopCondition(a)
}

func newAfiSafiInConditionFromApiStruct(a []*api.Family) (*table.AfiSafiInCondition, error) {
	if a == nil {
		return nil, nil
	}
	afiSafiTypes := make([]oc.AfiSafiType, 0, len(a))
	for _, aType := range a {
		rf := bgp.NewFamily(uint16(aType.Afi), uint8(aType.Safi))
		if configType, ok := bgp.AddressFamilyNameMap[rf]; ok {
			afiSafiTypes = append(afiSafiTypes, oc.AfiSafiType(configType))
		} else {
			return nil, fmt.Errorf("unknown afi-safi-in type value: %v", aType)
		}
	}
	return table.NewAfiSafiInCondition(afiSafiTypes)
}

func newRoutingActionFromApiStruct(a api.RouteAction) (*table.RoutingAction, error) {
	if a == api.RouteAction_ROUTE_ACTION_UNSPECIFIED {
		return nil, nil
	}
	accept := a == api.RouteAction_ROUTE_ACTION_ACCEPT

	return &table.RoutingAction{
		AcceptRoute: accept,
	}, nil
}

func apiCommunityActionToOcType(a api.CommunityAction_Type) (oc.BgpSetCommunityOptionType, error) {
	switch a {
	case api.CommunityAction_TYPE_UNSPECIFIED:
		return oc.BgpSetCommunityOptionType(""), status.Errorf(codes.InvalidArgument, "unspecified community action type")
	case api.CommunityAction_TYPE_ADD:
		return oc.BGP_SET_COMMUNITY_OPTION_TYPE_ADD, nil
	case api.CommunityAction_TYPE_REMOVE:
		return oc.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE, nil
	case api.CommunityAction_TYPE_REPLACE:
		return oc.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE, nil
	}
	return oc.BgpSetCommunityOptionType(""), status.Errorf(codes.InvalidArgument, "unknown community action type: %v", a)
}

func newCommunityActionFromApiStruct(a *api.CommunityAction) (*table.CommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	op, err := apiCommunityActionToOcType(a.Type)
	if err != nil {
		return nil, err
	}
	return table.NewCommunityAction(oc.SetCommunity{
		Options: string(op),
		SetCommunityMethod: oc.SetCommunityMethod{
			CommunitiesList: a.Communities,
		},
	})
}

func newExtCommunityActionFromApiStruct(a *api.CommunityAction) (*table.ExtCommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	op, err := apiCommunityActionToOcType(a.Type)
	if err != nil {
		return nil, err
	}
	return table.NewExtCommunityAction(oc.SetExtCommunity{
		Options: string(op),
		SetExtCommunityMethod: oc.SetExtCommunityMethod{
			CommunitiesList: a.Communities,
		},
	})
}

func newLargeCommunityActionFromApiStruct(a *api.CommunityAction) (*table.LargeCommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	op, err := apiCommunityActionToOcType(a.Type)
	if err != nil {
		return nil, err
	}
	return table.NewLargeCommunityAction(oc.SetLargeCommunity{
		Options: op,
		SetLargeCommunityMethod: oc.SetLargeCommunityMethod{
			CommunitiesList: a.Communities,
		},
	})
}

func newMedActionFromApiStruct(a *api.MedAction) (*table.MedAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewMedActionFromApiStruct(table.MedActionType(a.Type), a.Value), nil
}

func newLocalPrefActionFromApiStruct(a *api.LocalPrefAction) (*table.LocalPrefAction, error) {
	if a == nil || a.Value == 0 {
		return nil, nil
	}
	return table.NewLocalPrefAction(a.Value)
}

func newOriginActionFromApiStruct(a *api.OriginAction) (*table.OriginAction, error) {
	if a == nil {
		return nil, nil
	}

	var origin oc.BgpOriginAttrType
	switch v := a.GetOrigin(); v {
	case api.OriginType_ORIGIN_TYPE_UNSPECIFIED:
		return nil, nil
	case api.OriginType_ORIGIN_TYPE_IGP:
		origin = oc.BGP_ORIGIN_ATTR_TYPE_IGP
	case api.OriginType_ORIGIN_TYPE_EGP:
		origin = oc.BGP_ORIGIN_ATTR_TYPE_EGP
	case api.OriginType_ORIGIN_TYPE_INCOMPLETE:
		origin = oc.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE
	default:
		return nil, fmt.Errorf("unrecognized route origin type: %v", v)
	}

	return table.NewOriginAction(origin)
}

func newAsPathPrependActionFromApiStruct(a *api.AsPrependAction) (*table.AsPathPrependAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewAsPathPrependAction(oc.SetAsPathPrepend{
		RepeatN: uint8(a.Repeat),
		As: func() string {
			if a.UseLeftMost {
				return "last-as"
			}
			return fmt.Sprintf("%d", a.Asn)
		}(),
	})
}

func newNexthopActionFromApiStruct(a *api.NexthopAction) (*table.NexthopAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewNexthopAction(oc.BgpNextHopType(
		func() string {
			switch {
			case a.Self:
				return "self"
			case a.Unchanged:
				return "unchanged"
			case a.PeerAddress:
				return "peer-address"
			}
			return a.Address
		}(),
	))
}

func newStatementFromApiStruct(a *api.Statement) (*table.Statement, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty statement name")
	}
	var ra table.Action
	var as []table.Action
	var cs []table.Condition
	var err error
	if a.Conditions != nil {
		cfs := []func() (table.Condition, error){
			func() (table.Condition, error) {
				return newPrefixConditionFromApiStruct(a.Conditions.PrefixSet)
			},
			func() (table.Condition, error) {
				return newNeighborConditionFromApiStruct(a.Conditions.NeighborSet)
			},
			func() (table.Condition, error) {
				return newCommunityCountConditionFromApiStruct(a.Conditions.CommunityCount)
			},
			func() (table.Condition, error) {
				return newAsPathLengthConditionFromApiStruct(a.Conditions.AsPathLength)
			},
			func() (table.Condition, error) {
				return newRpkiValidationConditionFromApiStruct(a.Conditions.RpkiResult)
			},
			func() (table.Condition, error) {
				return newRouteTypeConditionFromApiStruct(a.Conditions.RouteType)
			},
			func() (table.Condition, error) {
				return newOriginConditionFromApiStruct(a.Conditions.Origin)
			},
			func() (table.Condition, error) {
				return newAsPathConditionFromApiStruct(a.Conditions.AsPathSet)
			},
			func() (table.Condition, error) {
				return newCommunityConditionFromApiStruct(a.Conditions.CommunitySet)
			},
			func() (table.Condition, error) {
				return newExtCommunityConditionFromApiStruct(a.Conditions.ExtCommunitySet)
			},
			func() (table.Condition, error) {
				return newLargeCommunityConditionFromApiStruct(a.Conditions.LargeCommunitySet)
			},
			func() (table.Condition, error) {
				return newNextHopConditionFromApiStruct(a.Conditions.NextHopInList)
			},
			func() (table.Condition, error) {
				return newAfiSafiInConditionFromApiStruct(a.Conditions.AfiSafiIn)
			},
			func() (table.Condition, error) {
				return newLocalPrefEqConditionFromApiStruct(a.Conditions.LocalPrefEq)
			},
			func() (table.Condition, error) {
				return newMedEqConditionFromApiStruct(a.Conditions.MedEq)
			},
		}
		cs = make([]table.Condition, 0, len(cfs))
		for _, f := range cfs {
			c, err := f()
			if err != nil {
				return nil, err
			}
			if !reflect.ValueOf(c).IsNil() {
				cs = append(cs, c)
			}
		}
	}
	if a.Actions != nil {
		ra, err = newRoutingActionFromApiStruct(a.Actions.RouteAction)
		if err != nil {
			return nil, err
		}
		afs := []func() (table.Action, error){
			func() (table.Action, error) {
				return newCommunityActionFromApiStruct(a.Actions.Community)
			},
			func() (table.Action, error) {
				return newExtCommunityActionFromApiStruct(a.Actions.ExtCommunity)
			},
			func() (table.Action, error) {
				return newLargeCommunityActionFromApiStruct(a.Actions.LargeCommunity)
			},
			func() (table.Action, error) {
				return newMedActionFromApiStruct(a.Actions.Med)
			},
			func() (table.Action, error) {
				return newLocalPrefActionFromApiStruct(a.Actions.LocalPref)
			},
			func() (table.Action, error) {
				return newAsPathPrependActionFromApiStruct(a.Actions.AsPrepend)
			},
			func() (table.Action, error) {
				return newNexthopActionFromApiStruct(a.Actions.Nexthop)
			},
			func() (table.Action, error) {
				return newOriginActionFromApiStruct(a.Actions.OriginAction)
			},
		}
		as = make([]table.Action, 0, len(afs))
		for _, f := range afs {
			a, err := f()
			if err != nil {
				return nil, err
			}
			if !reflect.ValueOf(a).IsNil() {
				as = append(as, a)
			}
		}
	}
	return &table.Statement{
		Name:        a.Name,
		Conditions:  cs,
		RouteAction: ra,
		ModActions:  as,
	}, nil
}

func (s *server) ListStatement(r *api.ListStatementRequest, stream api.GoBgpService_ListStatementServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(s *api.Statement) {
		if sendErr = stream.Send(&api.ListStatementResponse{Statement: s}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListStatement(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func (s *server) AddStatement(ctx context.Context, r *api.AddStatementRequest) (*api.AddStatementResponse, error) {
	return &api.AddStatementResponse{}, s.bgpServer.AddStatement(ctx, r)
}

func (s *server) DeleteStatement(ctx context.Context, r *api.DeleteStatementRequest) (*api.DeleteStatementResponse, error) {
	return &api.DeleteStatementResponse{}, s.bgpServer.DeleteStatement(ctx, r)
}

func newConfigPolicyFromApiStruct(a *api.Policy) (*oc.PolicyDefinition, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	stmts := make([]oc.Statement, 0, len(a.Statements))
	for idx, x := range a.Statements {
		if x.Name == "" {
			x.Name = fmt.Sprintf("%s_stmt%d", a.Name, idx)
		}
		y, err := newStatementFromApiStruct(x)
		if err != nil {
			return nil, err
		}
		stmt := y.ToConfig()
		stmts = append(stmts, *stmt)
	}
	return &oc.PolicyDefinition{
		Name:       a.Name,
		Statements: stmts,
	}, nil
}

func newPolicyFromApiStruct(a *api.Policy) (*table.Policy, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	stmts := make([]*table.Statement, 0, len(a.Statements))
	for idx, x := range a.Statements {
		if x.Name == "" {
			x.Name = fmt.Sprintf("%s_stmt%d", a.Name, idx)
		}
		y, err := newStatementFromApiStruct(x)
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, y)
	}
	return &table.Policy{
		Name:       a.Name,
		Statements: stmts,
	}, nil
}

func newRoaListFromTableStructList(origin []*table.ROA) []*api.Roa {
	l := make([]*api.Roa, 0)
	for _, r := range origin {
		host, portStr, _ := net.SplitHostPort(r.Src)
		port, _ := strconv.ParseUint(portStr, 10, 32)
		ones, _ := r.Network.Mask.Size()
		l = append(l, &api.Roa{
			Asn:       r.AS,
			Maxlen:    uint32(r.MaxLen),
			Prefixlen: uint32(ones),
			Prefix:    r.Network.IP.String(),
			Conf: &api.RPKIConf{
				Address:    host,
				RemotePort: uint32(port),
			},
		})
	}
	return l
}

func (s *server) ListPolicy(r *api.ListPolicyRequest, stream api.GoBgpService_ListPolicyServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(p *api.Policy) {
		if sendErr = stream.Send(&api.ListPolicyResponse{Policy: p}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListPolicy(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func (s *server) AddPolicy(ctx context.Context, r *api.AddPolicyRequest) (*api.AddPolicyResponse, error) {
	return &api.AddPolicyResponse{}, s.bgpServer.AddPolicy(ctx, r)
}

func (s *server) DeletePolicy(ctx context.Context, r *api.DeletePolicyRequest) (*api.DeletePolicyResponse, error) {
	return &api.DeletePolicyResponse{}, s.bgpServer.DeletePolicy(ctx, r)
}

func (s *server) ListPolicyAssignment(r *api.ListPolicyAssignmentRequest, stream api.GoBgpService_ListPolicyAssignmentServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	var sendErr error
	fn := func(a *api.PolicyAssignment) {
		if sendErr = stream.Send(&api.ListPolicyAssignmentResponse{Assignment: a}); sendErr != nil {
			cancel()
			return
		}
	}
	err := s.bgpServer.ListPolicyAssignment(ctx, r, fn)
	if sendErr != nil {
		return sendErr
	}
	return err
}

func defaultRouteType(d api.RouteAction) table.RouteType {
	switch d {
	case api.RouteAction_ROUTE_ACTION_ACCEPT:
		return table.ROUTE_TYPE_ACCEPT
	case api.RouteAction_ROUTE_ACTION_REJECT:
		return table.ROUTE_TYPE_REJECT
	default:
		return table.ROUTE_TYPE_NONE
	}
}

func toPolicyDefinition(policies []*api.Policy) []*oc.PolicyDefinition {
	l := make([]*oc.PolicyDefinition, 0, len(policies))
	for _, p := range policies {
		l = append(l, &oc.PolicyDefinition{Name: p.Name})
	}
	return l
}

func (s *server) AddPolicyAssignment(ctx context.Context, r *api.AddPolicyAssignmentRequest) (*api.AddPolicyAssignmentResponse, error) {
	return &api.AddPolicyAssignmentResponse{}, s.bgpServer.AddPolicyAssignment(ctx, r)
}

func (s *server) DeletePolicyAssignment(ctx context.Context, r *api.DeletePolicyAssignmentRequest) (*api.DeletePolicyAssignmentResponse, error) {
	return &api.DeletePolicyAssignmentResponse{}, s.bgpServer.DeletePolicyAssignment(ctx, r)
}

func (s *server) SetPolicyAssignment(ctx context.Context, r *api.SetPolicyAssignmentRequest) (*api.SetPolicyAssignmentResponse, error) {
	return &api.SetPolicyAssignmentResponse{}, s.bgpServer.SetPolicyAssignment(ctx, r)
}

func (s *server) GetBgp(ctx context.Context, r *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	return s.bgpServer.GetBgp(ctx, r)
}

func newGlobalFromAPIStruct(a *api.Global) *oc.Global {
	families := make([]oc.AfiSafi, 0, len(a.Families))
	for _, f := range a.Families {
		name := oc.IntToAfiSafiTypeMap[int(f)]
		rf, _ := bgp.GetFamily(string(name))
		families = append(families, oc.AfiSafi{
			Config: oc.AfiSafiConfig{
				AfiSafiName: name,
				Enabled:     true,
			},
			State: oc.AfiSafiState{
				AfiSafiName: name,
				Enabled:     true,
				Family:      rf,
			},
		})
	}

	l := make([]netip.Addr, 0, len(a.ListenAddresses))
	for _, addr := range a.ListenAddresses {
		l = append(l, netip.MustParseAddr(addr))
	}

	global := &oc.Global{
		Config: oc.GlobalConfig{
			As:               a.Asn,
			RouterId:         netip.MustParseAddr(a.RouterId),
			Port:             a.ListenPort,
			LocalAddressList: l,
		},
		AfiSafis: families,
		UseMultiplePaths: oc.UseMultiplePaths{
			Config: oc.UseMultiplePathsConfig{
				Enabled: a.UseMultiplePaths,
			},
		},
	}
	if a.RouteSelectionOptions != nil {
		global.RouteSelectionOptions = oc.RouteSelectionOptions{
			Config: oc.RouteSelectionOptionsConfig{
				AlwaysCompareMed:         a.RouteSelectionOptions.AlwaysCompareMed,
				IgnoreAsPathLength:       a.RouteSelectionOptions.IgnoreAsPathLength,
				ExternalCompareRouterId:  a.RouteSelectionOptions.ExternalCompareRouterId,
				AdvertiseInactiveRoutes:  a.RouteSelectionOptions.AdvertiseInactiveRoutes,
				EnableAigp:               a.RouteSelectionOptions.EnableAigp,
				IgnoreNextHopIgpMetric:   a.RouteSelectionOptions.IgnoreNextHopIgpMetric,
				DisableBestPathSelection: a.RouteSelectionOptions.DisableBestPathSelection,
			},
		}
	}
	if a.DefaultRouteDistance != nil {
		global.DefaultRouteDistance = oc.DefaultRouteDistance{
			Config: oc.DefaultRouteDistanceConfig{
				ExternalRouteDistance: uint8(a.DefaultRouteDistance.ExternalRouteDistance),
				InternalRouteDistance: uint8(a.DefaultRouteDistance.InternalRouteDistance),
			},
		}
	}
	if a.Confederation != nil {
		global.Confederation = oc.Confederation{
			Config: oc.ConfederationConfig{
				Enabled:      a.Confederation.Enabled,
				Identifier:   a.Confederation.Identifier,
				MemberAsList: a.Confederation.MemberAsList,
			},
		}
	}
	if a.GracefulRestart != nil {
		global.GracefulRestart = oc.GracefulRestart{
			Config: oc.GracefulRestartConfig{
				Enabled:             a.GracefulRestart.Enabled,
				RestartTime:         uint16(a.GracefulRestart.RestartTime),
				StaleRoutesTime:     float64(a.GracefulRestart.StaleRoutesTime),
				HelperOnly:          a.GracefulRestart.HelperOnly,
				DeferralTime:        uint16(a.GracefulRestart.DeferralTime),
				NotificationEnabled: a.GracefulRestart.NotificationEnabled,
				LongLivedEnabled:    a.GracefulRestart.LonglivedEnabled,
			},
		}
	}
	return global
}

func (s *server) StartBgp(ctx context.Context, r *api.StartBgpRequest) (*api.StartBgpResponse, error) {
	return &api.StartBgpResponse{}, s.bgpServer.StartBgp(ctx, r)
}

func (s *server) StopBgp(ctx context.Context, r *api.StopBgpRequest) (*api.StopBgpResponse, error) {
	return &api.StopBgpResponse{}, s.bgpServer.StopBgp(ctx, r)
}

func (s *server) GetTable(ctx context.Context, r *api.GetTableRequest) (*api.GetTableResponse, error) {
	return s.bgpServer.GetTable(ctx, r)
}

func (s *server) SetLogLevel(ctx context.Context, r *api.SetLogLevelRequest) (*api.SetLogLevelResponse, error) {
	return &api.SetLogLevelResponse{}, s.bgpServer.SetLogLevel(ctx, r)
}

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
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgryski/go-farm"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	apb "google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	tspb "google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/internal/pkg/config"
	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type server struct {
	bgpServer  *BgpServer
	grpcServer *grpc.Server
	hosts      string
	api.UnimplementedGobgpApiServer
}

func newAPIserver(b *BgpServer, g *grpc.Server, hosts string) *server {
	grpc.EnableTracing = false
	s := &server{
		bgpServer:  b,
		grpcServer: g,
		hosts:      hosts,
	}
	api.RegisterGobgpApiServer(g, s)
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
				log.Fields{
					"Topic": "grpc",
					"Key":   host,
					"Error": err})
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
		s.bgpServer.logger.Warn("accept failed",
			log.Fields{
				"Topic": "grpc",
				"Key":   lis,
				"Error": err})
	}

	for _, lis := range l {
		go serve(lis)
	}
	wg.Wait()
	return nil
}

func (s *server) ListDynamicNeighbor(r *api.ListDynamicNeighborRequest, stream api.GobgpApi_ListDynamicNeighborServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(dn *api.DynamicNeighbor) {
		if err := stream.Send(&api.ListDynamicNeighborResponse{DynamicNeighbor: dn}); err != nil {
			cancel()
			return
		}
	}
	return s.bgpServer.ListDynamicNeighbor(ctx, r, fn)
}

func (s *server) ListPeerGroup(r *api.ListPeerGroupRequest, stream api.GobgpApi_ListPeerGroupServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(pg *api.PeerGroup) {
		if err := stream.Send(&api.ListPeerGroupResponse{PeerGroup: pg}); err != nil {
			cancel()
			return
		}
	}
	return s.bgpServer.ListPeerGroup(ctx, r, fn)
}

func parseHost(host string) (string, string) {
	const unixScheme = "unix://"
	if strings.HasPrefix(host, unixScheme) {
		return "unix", host[len(unixScheme):]
	}
	return "tcp", host
}

func (s *server) ListPeer(r *api.ListPeerRequest, stream api.GobgpApi_ListPeerServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(p *api.Peer) {
		if err := stream.Send(&api.ListPeerResponse{Peer: p}); err != nil {
			cancel()
			return
		}
	}
	return s.bgpServer.ListPeer(ctx, r, fn)
}

func newValidationFromTableStruct(v *table.Validation) *api.Validation {
	if v == nil {
		return &api.Validation{}
	}
	return &api.Validation{
		State:           api.Validation_State(v.Status.ToInt()),
		Reason:          api.Validation_Reason(v.Reason.ToInt()),
		Matched:         newRoaListFromTableStructList(v.Matched),
		UnmatchedAsn:    newRoaListFromTableStructList(v.UnmatchedAs),
		UnmatchedLength: newRoaListFromTableStructList(v.UnmatchedLength),
	}
}

func toPathAPI(binNlri []byte, binPattrs [][]byte, anyNlri *apb.Any, anyPattrs []*apb.Any, path *table.Path, v *table.Validation) *api.Path {
	nlri := path.GetNlri()
	p := &api.Path{
		Nlri:               anyNlri,
		Pattrs:             anyPattrs,
		Age:                tspb.New(path.GetTimestamp()),
		IsWithdraw:         path.IsWithdraw,
		Validation:         newValidationFromTableStruct(v),
		Family:             &api.Family{Afi: api.Family_Afi(nlri.AFI()), Safi: api.Family_Safi(nlri.SAFI())},
		Stale:              path.IsStale(),
		IsFromExternal:     path.IsFromExternal(),
		NoImplicitWithdraw: path.NoImplicitWithdraw(),
		IsNexthopInvalid:   path.IsNexthopInvalid,
		Identifier:         nlri.PathIdentifier(),
		LocalIdentifier:    nlri.PathLocalIdentifier(),
		NlriBinary:         binNlri,
		PattrsBinary:       binPattrs,
	}
	if s := path.GetSource(); s != nil {
		p.SourceAsn = s.AS
		p.SourceId = s.ID.String()
		p.NeighborIp = s.Address.String()
	}
	return p
}

func toPathApi(path *table.Path, v *table.Validation, onlyBinary, nlriBinary, attributeBinary bool) *api.Path {
	var (
		anyNlri   *apb.Any
		anyPattrs []*apb.Any
	)
	nlri := path.GetNlri()
	if !onlyBinary {
		anyNlri, _ = apiutil.MarshalNLRI(nlri)
		anyPattrs, _ = apiutil.MarshalPathAttributes(path.GetPathAttrs())
	}
	var binNlri []byte
	if onlyBinary || nlriBinary {
		binNlri, _ = nlri.Serialize()
	}
	var binPattrs [][]byte
	if onlyBinary || attributeBinary {
		pa := path.GetPathAttrs()
		binPattrs = make([][]byte, 0, len(pa))
		for _, a := range pa {
			b, e := a.Serialize()
			if e == nil {
				binPattrs = append(binPattrs, b)
			}
		}
	}
	return toPathAPI(binNlri, binPattrs, anyNlri, anyPattrs, path, v)
}

func getValidation(v map[*table.Path]*table.Validation, p *table.Path) *table.Validation {
	if v == nil {
		return nil
	} else {
		return v[p]
	}
}

func (s *server) ListPath(r *api.ListPathRequest, stream api.GobgpApi_ListPathServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := make([]*api.Destination, 0)
	err := s.bgpServer.ListPath(ctx, r, func(d *api.Destination) {
		l = append(l, d)
	})
	if err != nil {
		return err
	}
	for _, d := range l {
		if err := stream.Send(&api.ListPathResponse{Destination: d}); err != nil {
			break
		}
	}
	return err
}

func (s *server) WatchEvent(r *api.WatchEventRequest, stream api.GobgpApi_WatchEventServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	s.bgpServer.WatchEvent(ctx, r, func(rsp *api.WatchEventResponse) {
		if err := stream.Send(rsp); err != nil {
			cancel()
			return
		}
	})
	<-ctx.Done()
	return nil
}

func (s *server) ResetPeer(ctx context.Context, r *api.ResetPeerRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.ResetPeer(ctx, r)
}

func (s *server) ShutdownPeer(ctx context.Context, r *api.ShutdownPeerRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.ShutdownPeer(ctx, r)
}

func (s *server) EnablePeer(ctx context.Context, r *api.EnablePeerRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.EnablePeer(ctx, r)
}

func (s *server) DisablePeer(ctx context.Context, r *api.DisablePeerRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DisablePeer(ctx, r)
}

func (s *server) SetPolicies(ctx context.Context, r *api.SetPoliciesRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.SetPolicies(ctx, r)
}

func newRoutingPolicyFromApiStruct(arg *api.SetPoliciesRequest) (*config.RoutingPolicy, error) {
	policyDefinitions := make([]config.PolicyDefinition, 0, len(arg.Policies))
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

	return &config.RoutingPolicy{
		DefinedSets:       *definedSets,
		PolicyDefinitions: policyDefinitions,
	}, nil
}

func api2Path(resource api.TableType, path *api.Path, isWithdraw bool) (*table.Path, error) {
	var pi *table.PeerInfo
	var nlri bgp.AddrPrefixInterface
	var nexthop string

	if path.SourceAsn != 0 {
		pi = &table.PeerInfo{
			AS: path.SourceAsn,
			ID: net.ParseIP(path.SourceId),
		}
	}

	nlri, err := apiutil.GetNativeNlri(path)
	if err != nil {
		return nil, err
	}
	nlri.SetPathIdentifier(path.Identifier)

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
			nexthop = a.Value.String()
		case *bgp.PathAttributeMpReachNLRI:
			if len(a.Value) == 0 {
				return nil, fmt.Errorf("invalid mp reach attribute")
			}
			nexthop = a.Nexthop.String()
		default:
			pattrs = append(pattrs, attr)
		}
	}

	if nlri == nil {
		return nil, fmt.Errorf("nlri not found")
	} else if !path.IsWithdraw && nexthop == "" {
		return nil, fmt.Errorf("nexthop not found")
	}
	rf := bgp.AfiSafiToRouteFamily(uint16(path.Family.Afi), uint8(path.Family.Safi))
	if resource != api.TableType_VRF && rf == bgp.RF_IPv4_UC && net.ParseIP(nexthop).To4() != nil {
		pattrs = append(pattrs, bgp.NewPathAttributeNextHop(nexthop))
	} else {
		pattrs = append(pattrs, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
	}

	doWithdraw := (isWithdraw || path.IsWithdraw)
	newPath := table.NewPath(pi, nlri, doWithdraw, pattrs, time.Now(), path.NoImplicitWithdraw)
	if !doWithdraw {
		total := bytes.NewBuffer(make([]byte, 0))
		for _, a := range newPath.GetPathAttrs() {
			if a.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
				continue
			}
			b, _ := a.Serialize()
			total.Write(b)
		}
		newPath.SetHash(farm.Hash32(total.Bytes()))
	}
	newPath.SetIsFromExternal(path.IsFromExternal)
	return newPath, nil
}

func (s *server) AddPath(ctx context.Context, r *api.AddPathRequest) (*api.AddPathResponse, error) {
	return s.bgpServer.AddPath(ctx, r)
}

func (s *server) DeletePath(ctx context.Context, r *api.DeletePathRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeletePath(ctx, r)
}

func (s *server) EnableMrt(ctx context.Context, r *api.EnableMrtRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.EnableMrt(ctx, r)
}

func (s *server) DisableMrt(ctx context.Context, r *api.DisableMrtRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DisableMrt(ctx, r)
}

func (s *server) AddPathStream(stream api.GobgpApi_AddPathStreamServer) error {
	for {
		arg, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if arg.TableType != api.TableType_GLOBAL && arg.TableType != api.TableType_VRF {
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
	return stream.SendAndClose(&emptypb.Empty{})
}

func (s *server) AddBmp(ctx context.Context, r *api.AddBmpRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddBmp(ctx, r)
}

func (s *server) DeleteBmp(ctx context.Context, r *api.DeleteBmpRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeleteBmp(ctx, r)
}

func (s *server) ListBmp(r *api.ListBmpRequest, stream api.GobgpApi_ListBmpServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(rsp *api.ListBmpResponse_BmpStation) {
		if err := stream.Send(&api.ListBmpResponse{Station: rsp}); err != nil {
			cancel()
		}
	}
	return s.bgpServer.ListBmp(ctx, r, fn)
}

func (s *server) AddRpki(ctx context.Context, r *api.AddRpkiRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddRpki(ctx, r)
}

func (s *server) DeleteRpki(ctx context.Context, r *api.DeleteRpkiRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeleteRpki(ctx, r)
}

func (s *server) EnableRpki(ctx context.Context, r *api.EnableRpkiRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.EnableRpki(ctx, r)
}

func (s *server) DisableRpki(ctx context.Context, r *api.DisableRpkiRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DisableRpki(ctx, r)
}

func (s *server) ResetRpki(ctx context.Context, r *api.ResetRpkiRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.ResetRpki(ctx, r)
}

func (s *server) ListRpki(r *api.ListRpkiRequest, stream api.GobgpApi_ListRpkiServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(r *api.Rpki) {
		if err := stream.Send(&api.ListRpkiResponse{Server: r}); err != nil {
			cancel()
		}
	}
	return s.bgpServer.ListRpki(ctx, r, fn)
}

func (s *server) ListRpkiTable(r *api.ListRpkiTableRequest, stream api.GobgpApi_ListRpkiTableServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(r *api.Roa) {
		if err := stream.Send(&api.ListRpkiTableResponse{Roa: r}); err != nil {
			cancel()
		}
	}
	return s.bgpServer.ListRpkiTable(ctx, r, fn)
}

func (s *server) EnableZebra(ctx context.Context, r *api.EnableZebraRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.EnableZebra(ctx, r)
}

func (s *server) ListVrf(r *api.ListVrfRequest, stream api.GobgpApi_ListVrfServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(v *api.Vrf) {
		if err := stream.Send(&api.ListVrfResponse{Vrf: v}); err != nil {
			cancel()
		}
	}
	return s.bgpServer.ListVrf(ctx, r, fn)
}

func (s *server) AddVrf(ctx context.Context, r *api.AddVrfRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddVrf(ctx, r)
}

func (s *server) DeleteVrf(ctx context.Context, r *api.DeleteVrfRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeleteVrf(ctx, r)
}

func readMpGracefulRestartFromAPIStruct(c *config.MpGracefulRestart, a *api.MpGracefulRestart) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
	}
}

func readAfiSafiConfigFromAPIStruct(c *config.AfiSafiConfig, a *api.AfiSafiConfig) {
	if c == nil || a == nil {
		return
	}
	rf := bgp.AfiSafiToRouteFamily(uint16(a.Family.Afi), uint8(a.Family.Safi))
	c.AfiSafiName = config.AfiSafiType(rf.String())
	c.Enabled = a.Enabled
}

func readAfiSafiStateFromAPIStruct(s *config.AfiSafiState, a *api.AfiSafiConfig) {
	if s == nil || a == nil {
		return
	}
	// Store only address family value for the convenience
	s.Family = bgp.AfiSafiToRouteFamily(uint16(a.Family.Afi), uint8(a.Family.Safi))
}

func readPrefixLimitFromAPIStruct(c *config.PrefixLimit, a *api.PrefixLimit) {
	if c == nil || a == nil {
		return
	}
	c.Config.MaxPrefixes = a.MaxPrefixes
	c.Config.ShutdownThresholdPct = config.Percentage(a.ShutdownThresholdPct)
}

func readApplyPolicyFromAPIStruct(c *config.ApplyPolicy, a *api.ApplyPolicy) {
	if c == nil || a == nil {
		return
	}
	f := func(a api.RouteAction) config.DefaultPolicyType {
		if a == api.RouteAction_ACCEPT {
			return config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
		} else if a == api.RouteAction_REJECT {
			return config.DEFAULT_POLICY_TYPE_REJECT_ROUTE
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
	if a.InPolicy != nil {
		c.Config.DefaultInPolicy = f(a.InPolicy.DefaultAction)
		for _, p := range a.InPolicy.Policies {
			c.Config.InPolicyList = append(c.Config.InPolicyList, p.Name)
		}
	}
}

func readRouteSelectionOptionsFromAPIStruct(c *config.RouteSelectionOptions, a *api.RouteSelectionOptions) {
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

func readUseMultiplePathsFromAPIStruct(c *config.UseMultiplePaths, a *api.UseMultiplePaths) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
	}
	if a.Ebgp != nil && a.Ebgp.Config != nil {
		c.Ebgp = config.Ebgp{
			Config: config.EbgpConfig{
				AllowMultipleAs: a.Ebgp.Config.AllowMultipleAsn,
				MaximumPaths:    a.Ebgp.Config.MaximumPaths,
			},
		}
	}
	if a.Ibgp != nil && a.Ibgp.Config != nil {
		c.Ibgp = config.Ibgp{
			Config: config.IbgpConfig{
				MaximumPaths: a.Ibgp.Config.MaximumPaths,
			},
		}
	}
}

func readRouteTargetMembershipFromAPIStruct(c *config.RouteTargetMembership, a *api.RouteTargetMembership) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.DeferralTime = uint16(a.Config.DeferralTime)
	}
}

func readLongLivedGracefulRestartFromAPIStruct(c *config.LongLivedGracefulRestart, a *api.LongLivedGracefulRestart) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
		c.Config.RestartTime = a.Config.RestartTime
	}
}

func readAddPathsFromAPIStruct(c *config.AddPaths, a *api.AddPaths) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Receive = a.Config.Receive
		c.Config.SendMax = uint8(a.Config.SendMax)
	}
}

func newNeighborFromAPIStruct(a *api.Peer) (*config.Neighbor, error) {
	pconf := &config.Neighbor{}
	if a.Conf != nil {
		pconf.Config.PeerAs = a.Conf.PeerAsn
		pconf.Config.LocalAs = a.Conf.LocalAsn
		pconf.Config.AuthPassword = a.Conf.AuthPassword
		pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
		pconf.Config.Description = a.Conf.Description
		pconf.Config.PeerGroup = a.Conf.PeerGroup
		pconf.Config.PeerType = config.IntToPeerTypeMap[int(a.Conf.Type)]
		pconf.Config.NeighborAddress = a.Conf.NeighborAddress
		pconf.Config.AdminDown = a.Conf.AdminDown
		pconf.Config.NeighborInterface = a.Conf.NeighborInterface
		pconf.Config.Vrf = a.Conf.Vrf
		pconf.AsPathOptions.Config.AllowOwnAs = uint8(a.Conf.AllowOwnAsn)
		pconf.AsPathOptions.Config.ReplacePeerAs = a.Conf.ReplacePeerAsn

		switch a.Conf.RemovePrivate {
		case api.RemovePrivate_REMOVE_ALL:
			pconf.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_ALL
		case api.RemovePrivate_REPLACE:
			pconf.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_REPLACE
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

			pconf.State.RemoteRouterId = a.State.RouterId
		}

		for _, af := range a.AfiSafis {
			afiSafi := config.AfiSafi{}
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
		}
		if a.Timers.State != nil {
			pconf.Timers.State.KeepaliveInterval = float64(a.Timers.State.KeepaliveInterval)
			pconf.Timers.State.NegotiatedHoldTime = float64(a.Timers.State.NegotiatedHoldTime)
		}
	}
	if a.RouteReflector != nil {
		pconf.RouteReflector.Config.RouteReflectorClusterId = config.RrClusterIdType(a.RouteReflector.RouteReflectorClusterId)
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
		pconf.Transport.Config.LocalAddress = a.Transport.LocalAddress
		pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
		pconf.Transport.Config.RemotePort = uint16(a.Transport.RemotePort)
		pconf.Transport.Config.LocalPort = uint16(a.Transport.LocalPort)
		pconf.Transport.Config.BindInterface = a.Transport.BindInterface
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
		pconf.State.SessionState = config.SessionState(strings.ToUpper(string(a.State.SessionState)))
		pconf.State.AdminState = config.IntToAdminStateMap[int(a.State.AdminState)]

		pconf.State.PeerAs = a.State.PeerAsn
		pconf.State.PeerType = config.IntToPeerTypeMap[int(a.State.Type)]
		pconf.State.NeighborAddress = a.State.NeighborAddress

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

func newPeerGroupFromAPIStruct(a *api.PeerGroup) (*config.PeerGroup, error) {
	pconf := &config.PeerGroup{}
	if a.Conf != nil {
		pconf.Config.PeerAs = a.Conf.PeerAsn
		pconf.Config.LocalAs = a.Conf.LocalAsn
		pconf.Config.AuthPassword = a.Conf.AuthPassword
		pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
		pconf.Config.Description = a.Conf.Description
		pconf.Config.PeerGroupName = a.Conf.PeerGroupName

		switch a.Conf.RemovePrivate {
		case api.RemovePrivate_REMOVE_ALL:
			pconf.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_ALL
		case api.RemovePrivate_REPLACE:
			pconf.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_REPLACE
		}

		for _, af := range a.AfiSafis {
			afiSafi := config.AfiSafi{}
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
		}
		if a.Timers.State != nil {
			pconf.Timers.State.KeepaliveInterval = float64(a.Timers.State.KeepaliveInterval)
			pconf.Timers.State.NegotiatedHoldTime = float64(a.Timers.State.NegotiatedHoldTime)
		}
	}
	if a.RouteReflector != nil {
		pconf.RouteReflector.Config.RouteReflectorClusterId = config.RrClusterIdType(a.RouteReflector.RouteReflectorClusterId)
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
		pconf.Transport.Config.LocalAddress = a.Transport.LocalAddress
		pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
		pconf.Transport.Config.RemotePort = uint16(a.Transport.RemotePort)
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
		pconf.State.PeerType = config.IntToPeerTypeMap[int(a.Info.Type)]
	}
	return pconf, nil
}

func (s *server) AddPeer(ctx context.Context, r *api.AddPeerRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddPeer(ctx, r)
}

func (s *server) DeletePeer(ctx context.Context, r *api.DeletePeerRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeletePeer(ctx, r)
}

func (s *server) UpdatePeer(ctx context.Context, r *api.UpdatePeerRequest) (*api.UpdatePeerResponse, error) {
	return s.bgpServer.UpdatePeer(ctx, r)
}

func (s *server) AddPeerGroup(ctx context.Context, r *api.AddPeerGroupRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddPeerGroup(ctx, r)
}

func (s *server) DeletePeerGroup(ctx context.Context, r *api.DeletePeerGroupRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeletePeerGroup(ctx, r)
}

func (s *server) UpdatePeerGroup(ctx context.Context, r *api.UpdatePeerGroupRequest) (*api.UpdatePeerGroupResponse, error) {
	return s.bgpServer.UpdatePeerGroup(ctx, r)
}

func (s *server) AddDynamicNeighbor(ctx context.Context, r *api.AddDynamicNeighborRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddDynamicNeighbor(ctx, r)
}

func (s *server) DeleteDynamicNeighbor(ctx context.Context, r *api.DeleteDynamicNeighborRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeleteDynamicNeighbor(ctx, r)
}

func newPrefixFromApiStruct(a *api.Prefix) (*table.Prefix, error) {
	_, prefix, err := net.ParseCIDR(a.IpPrefix)
	if err != nil {
		return nil, err
	}
	rf := bgp.RF_IPv4_UC
	if strings.Contains(a.IpPrefix, ":") {
		rf = bgp.RF_IPv6_UC
	}
	return &table.Prefix{
		Prefix:             prefix,
		AddressFamily:      rf,
		MasklengthRangeMin: uint8(a.MaskLengthMin),
		MasklengthRangeMax: uint8(a.MaskLengthMax),
	}, nil
}

func newConfigPrefixFromAPIStruct(a *api.Prefix) (*config.Prefix, error) {
	_, prefix, err := net.ParseCIDR(a.IpPrefix)
	if err != nil {
		return nil, err
	}
	return &config.Prefix{
		IpPrefix:        prefix.String(),
		MasklengthRange: fmt.Sprintf("%d..%d", a.MaskLengthMin, a.MaskLengthMax),
	}, nil
}

func newConfigDefinedSetsFromApiStruct(a []*api.DefinedSet) (*config.DefinedSets, error) {
	ps := make([]config.PrefixSet, 0)
	ns := make([]config.NeighborSet, 0)
	as := make([]config.AsPathSet, 0)
	cs := make([]config.CommunitySet, 0)
	es := make([]config.ExtCommunitySet, 0)
	ls := make([]config.LargeCommunitySet, 0)

	for _, ds := range a {
		if ds.Name == "" {
			return nil, fmt.Errorf("empty neighbor set name")
		}
		switch table.DefinedType(ds.DefinedType) {
		case table.DEFINED_TYPE_PREFIX:
			prefixes := make([]config.Prefix, 0, len(ds.Prefixes))
			for _, p := range ds.Prefixes {
				prefix, err := newConfigPrefixFromAPIStruct(p)
				if err != nil {
					return nil, err
				}
				prefixes = append(prefixes, *prefix)
			}
			ps = append(ps, config.PrefixSet{
				PrefixSetName: ds.Name,
				PrefixList:    prefixes,
			})
		case table.DEFINED_TYPE_NEIGHBOR:
			ns = append(ns, config.NeighborSet{
				NeighborSetName:  ds.Name,
				NeighborInfoList: ds.List,
			})
		case table.DEFINED_TYPE_AS_PATH:
			as = append(as, config.AsPathSet{
				AsPathSetName: ds.Name,
				AsPathList:    ds.List,
			})
		case table.DEFINED_TYPE_COMMUNITY:
			cs = append(cs, config.CommunitySet{
				CommunitySetName: ds.Name,
				CommunityList:    ds.List,
			})
		case table.DEFINED_TYPE_EXT_COMMUNITY:
			es = append(es, config.ExtCommunitySet{
				ExtCommunitySetName: ds.Name,
				ExtCommunityList:    ds.List,
			})
		case table.DEFINED_TYPE_LARGE_COMMUNITY:
			ls = append(ls, config.LargeCommunitySet{
				LargeCommunitySetName: ds.Name,
				LargeCommunityList:    ds.List,
			})
		default:
			return nil, fmt.Errorf("invalid defined type")
		}
	}

	return &config.DefinedSets{
		PrefixSets:   ps,
		NeighborSets: ns,
		BgpDefinedSets: config.BgpDefinedSets{
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
	switch table.DefinedType(a.DefinedType) {
	case table.DEFINED_TYPE_PREFIX:
		prefixes := make([]*table.Prefix, 0, len(a.Prefixes))
		for _, p := range a.Prefixes {
			prefix, err := newPrefixFromApiStruct(p)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix)
		}
		return table.NewPrefixSetFromApiStruct(a.Name, prefixes)
	case table.DEFINED_TYPE_NEIGHBOR:
		list := make([]net.IPNet, 0, len(a.List))
		for _, x := range a.List {
			_, addr, err := net.ParseCIDR(x)
			if err != nil {
				return nil, fmt.Errorf("invalid address or prefix: %s", x)
			}
			list = append(list, *addr)
		}
		return table.NewNeighborSetFromApiStruct(a.Name, list)
	case table.DEFINED_TYPE_AS_PATH:
		return table.NewAsPathSet(config.AsPathSet{
			AsPathSetName: a.Name,
			AsPathList:    a.List,
		})
	case table.DEFINED_TYPE_COMMUNITY:
		return table.NewCommunitySet(config.CommunitySet{
			CommunitySetName: a.Name,
			CommunityList:    a.List,
		})
	case table.DEFINED_TYPE_EXT_COMMUNITY:
		return table.NewExtCommunitySet(config.ExtCommunitySet{
			ExtCommunitySetName: a.Name,
			ExtCommunityList:    a.List,
		})
	case table.DEFINED_TYPE_LARGE_COMMUNITY:
		return table.NewLargeCommunitySet(config.LargeCommunitySet{
			LargeCommunitySetName: a.Name,
			LargeCommunityList:    a.List,
		})
	default:
		return nil, fmt.Errorf("invalid defined type")
	}
}

var _regexpPrefixMaskLengthRange = regexp.MustCompile(`(\d+)\.\.(\d+)`)

func (s *server) ListDefinedSet(r *api.ListDefinedSetRequest, stream api.GobgpApi_ListDefinedSetServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(d *api.DefinedSet) {
		if err := stream.Send(&api.ListDefinedSetResponse{DefinedSet: d}); err != nil {
			cancel()
		}
	}
	return s.bgpServer.ListDefinedSet(ctx, r, fn)
}

func (s *server) AddDefinedSet(ctx context.Context, r *api.AddDefinedSetRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddDefinedSet(ctx, r)
}

func (s *server) DeleteDefinedSet(ctx context.Context, r *api.DeleteDefinedSetRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeleteDefinedSet(ctx, r)
}

var _regexpMedActionType = regexp.MustCompile(`([+-]?)(\d+)`)

func matchSetOptionsRestrictedTypeToAPI(t config.MatchSetOptionsRestrictedType) api.MatchSet_Type {
	t = t.DefaultAsNeeded()
	switch t {
	case config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY:
		return api.MatchSet_ANY
	case config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT:
		return api.MatchSet_INVERT
	}
	return api.MatchSet_ANY
}

func toStatementApi(s *config.Statement) *api.Statement {
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
	if s.Conditions.BgpConditions.AsPathLength.Operator != "" {
		cs.AsPathLength = &api.AsPathLength{
			Length: s.Conditions.BgpConditions.AsPathLength.Value,
			Type:   api.AsPathLength_Type(s.Conditions.BgpConditions.AsPathLength.Operator.ToInt()),
		}
	}
	if s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet != "" {
		cs.AsPathSet = &api.MatchSet{
			Type: api.MatchSet_Type(s.Conditions.BgpConditions.MatchAsPathSet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet,
		}
	}
	if s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet != "" {
		cs.CommunitySet = &api.MatchSet{
			Type: api.MatchSet_Type(s.Conditions.BgpConditions.MatchCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet != "" {
		cs.ExtCommunitySet = &api.MatchSet{
			Type: api.MatchSet_Type(s.Conditions.BgpConditions.MatchExtCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet != "" {
		cs.LargeCommunitySet = &api.MatchSet{
			Type: api.MatchSet_Type(s.Conditions.BgpConditions.MatchLargeCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.RouteType != "" {
		cs.RouteType = api.Conditions_RouteType(s.Conditions.BgpConditions.RouteType.ToInt())
	}
	if len(s.Conditions.BgpConditions.NextHopInList) > 0 {
		cs.NextHopInList = s.Conditions.BgpConditions.NextHopInList
	}
	if s.Conditions.BgpConditions.AfiSafiInList != nil {
		afiSafiIn := make([]*api.Family, 0)
		for _, afiSafiType := range s.Conditions.BgpConditions.AfiSafiInList {
			if mapped, ok := bgp.AddressFamilyValueMap[string(afiSafiType)]; ok {
				afi, safi := bgp.RouteFamilyToAfiSafi(mapped)
				afiSafiIn = append(afiSafiIn, &api.Family{Afi: api.Family_Afi(afi), Safi: api.Family_Safi(safi)})
			}
		}
		cs.AfiSafiIn = afiSafiIn
	}
	cs.RpkiResult = int32(s.Conditions.BgpConditions.RpkiValidationResult.ToInt())
	as := &api.Actions{
		RouteAction: func() api.RouteAction {
			switch s.Actions.RouteDisposition {
			case config.ROUTE_DISPOSITION_ACCEPT_ROUTE:
				return api.RouteAction_ACCEPT
			case config.ROUTE_DISPOSITION_REJECT_ROUTE:
				return api.RouteAction_REJECT
			}
			return api.RouteAction_NONE
		}(),
		Community: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityAction_Type(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList}
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
			action := api.MedAction_REPLACE
			switch matches[1] {
			case "+", "-":
				action = api.MedAction_MOD
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
				Type:        api.CommunityAction_Type(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetExtCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList,
			}
		}(),
		LargeCommunity: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityAction_Type(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetLargeCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList,
			}
		}(),
		Nexthop: func() *api.NexthopAction {
			if len(string(s.Actions.BgpActions.SetNextHop)) == 0 {
				return nil
			}

			if string(s.Actions.BgpActions.SetNextHop) == "self" {
				return &api.NexthopAction{
					Self: true,
				}
			}
			if string(s.Actions.BgpActions.SetNextHop) == "unchanged" {
				return &api.NexthopAction{
					Unchanged: true,
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
	}
	return &api.Statement{
		Name:       s.Name,
		Conditions: cs,
		Actions:    as,
	}
}

func toConfigMatchSetOption(a api.MatchSet_Type) (config.MatchSetOptionsType, error) {
	var typ config.MatchSetOptionsType
	switch a {
	case api.MatchSet_ANY:
		typ = config.MATCH_SET_OPTIONS_TYPE_ANY
	case api.MatchSet_ALL:
		typ = config.MATCH_SET_OPTIONS_TYPE_ALL
	case api.MatchSet_INVERT:
		typ = config.MATCH_SET_OPTIONS_TYPE_INVERT
	default:
		return typ, fmt.Errorf("invalid match type")
	}
	return typ, nil
}

func toConfigMatchSetOptionRestricted(a api.MatchSet_Type) (config.MatchSetOptionsRestrictedType, error) {
	var typ config.MatchSetOptionsRestrictedType
	switch a {
	case api.MatchSet_ANY:
		typ = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	case api.MatchSet_INVERT:
		typ = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
	default:
		return typ, fmt.Errorf("invalid match type")
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
	c := config.MatchPrefixSet{
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
	c := config.MatchNeighborSet{
		NeighborSet:     a.Name,
		MatchSetOptions: typ,
	}
	return table.NewNeighborCondition(c)
}

func newAsPathLengthConditionFromApiStruct(a *api.AsPathLength) (*table.AsPathLengthCondition, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewAsPathLengthCondition(config.AsPathLength{
		Operator: config.IntToAttributeComparisonMap[int(a.Type)],
		Value:    a.Length,
	})
}

func newAsPathConditionFromApiStruct(a *api.MatchSet) (*table.AsPathCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchAsPathSet{
		AsPathSet:       a.Name,
		MatchSetOptions: typ,
	}
	return table.NewAsPathCondition(c)
}

func newRpkiValidationConditionFromApiStruct(a int32) (*table.RpkiValidationCondition, error) {
	if a < 1 {
		return nil, nil
	}
	return table.NewRpkiValidationCondition(config.IntToRpkiValidationResultTypeMap[int(a)])
}

func newRouteTypeConditionFromApiStruct(a api.Conditions_RouteType) (*table.RouteTypeCondition, error) {
	if a == 0 {
		return nil, nil
	}
	typ, ok := config.IntToRouteTypeMap[int(a)]
	if !ok {
		return nil, fmt.Errorf("invalid route type: %d", a)
	}
	return table.NewRouteTypeCondition(typ)
}

func newCommunityConditionFromApiStruct(a *api.MatchSet) (*table.CommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchCommunitySet{
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
	c := config.MatchExtCommunitySet{
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
	c := config.MatchLargeCommunitySet{
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
	afiSafiTypes := make([]config.AfiSafiType, 0, len(a))
	for _, aType := range a {
		rf := bgp.AfiSafiToRouteFamily(uint16(aType.Afi), uint8(aType.Safi))
		if configType, ok := bgp.AddressFamilyNameMap[bgp.RouteFamily(rf)]; ok {
			afiSafiTypes = append(afiSafiTypes, config.AfiSafiType(configType))
		} else {
			return nil, fmt.Errorf("unknown afi-safi-in type value: %v", aType)
		}
	}
	return table.NewAfiSafiInCondition(afiSafiTypes)
}

func newRoutingActionFromApiStruct(a api.RouteAction) (*table.RoutingAction, error) {
	if a == api.RouteAction_NONE {
		return nil, nil
	}
	accept := false
	if a == api.RouteAction_ACCEPT {
		accept = true
	}
	return &table.RoutingAction{
		AcceptRoute: accept,
	}, nil
}

func newCommunityActionFromApiStruct(a *api.CommunityAction) (*table.CommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewCommunityAction(config.SetCommunity{
		Options: string(config.IntToBgpSetCommunityOptionTypeMap[int(a.Type)]),
		SetCommunityMethod: config.SetCommunityMethod{
			CommunitiesList: a.Communities,
		},
	})
}

func newExtCommunityActionFromApiStruct(a *api.CommunityAction) (*table.ExtCommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewExtCommunityAction(config.SetExtCommunity{
		Options: string(config.IntToBgpSetCommunityOptionTypeMap[int(a.Type)]),
		SetExtCommunityMethod: config.SetExtCommunityMethod{
			CommunitiesList: a.Communities,
		},
	})
}

func newLargeCommunityActionFromApiStruct(a *api.CommunityAction) (*table.LargeCommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewLargeCommunityAction(config.SetLargeCommunity{
		Options: config.IntToBgpSetCommunityOptionTypeMap[int(a.Type)],
		SetLargeCommunityMethod: config.SetLargeCommunityMethod{
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

func newAsPathPrependActionFromApiStruct(a *api.AsPrependAction) (*table.AsPathPrependAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewAsPathPrependAction(config.SetAsPathPrepend{
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
	return table.NewNexthopAction(config.BgpNextHopType(
		func() string {
			if a.Self {
				return "self"
			}
			if a.Unchanged {
				return "unchanged"
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
				return newAsPathLengthConditionFromApiStruct(a.Conditions.AsPathLength)
			},
			func() (table.Condition, error) {
				return newRpkiValidationConditionFromApiStruct(a.Conditions.RpkiResult)
			},
			func() (table.Condition, error) {
				return newRouteTypeConditionFromApiStruct(a.Conditions.RouteType)
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

func (s *server) ListStatement(r *api.ListStatementRequest, stream api.GobgpApi_ListStatementServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(s *api.Statement) {
		if err := stream.Send(&api.ListStatementResponse{Statement: s}); err != nil {
			cancel()
		}
	}
	return s.bgpServer.ListStatement(ctx, r, fn)
}

func (s *server) AddStatement(ctx context.Context, r *api.AddStatementRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddStatement(ctx, r)
}

func (s *server) DeleteStatement(ctx context.Context, r *api.DeleteStatementRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeleteStatement(ctx, r)
}

func newConfigPolicyFromApiStruct(a *api.Policy) (*config.PolicyDefinition, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	stmts := make([]config.Statement, 0, len(a.Statements))
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
	return &config.PolicyDefinition{
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

func (s *server) ListPolicy(r *api.ListPolicyRequest, stream api.GobgpApi_ListPolicyServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(p *api.Policy) {
		if err := stream.Send(&api.ListPolicyResponse{Policy: p}); err != nil {
			cancel()
		}
	}
	return s.bgpServer.ListPolicy(ctx, r, fn)
}

func (s *server) AddPolicy(ctx context.Context, r *api.AddPolicyRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddPolicy(ctx, r)
}

func (s *server) DeletePolicy(ctx context.Context, r *api.DeletePolicyRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeletePolicy(ctx, r)
}

func (s *server) ListPolicyAssignment(r *api.ListPolicyAssignmentRequest, stream api.GobgpApi_ListPolicyAssignmentServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fn := func(a *api.PolicyAssignment) {
		if err := stream.Send(&api.ListPolicyAssignmentResponse{Assignment: a}); err != nil {
			cancel()
		}
	}
	return s.bgpServer.ListPolicyAssignment(ctx, r, fn)
}

func defaultRouteType(d api.RouteAction) table.RouteType {
	switch d {
	case api.RouteAction_ACCEPT:
		return table.ROUTE_TYPE_ACCEPT
	case api.RouteAction_REJECT:
		return table.ROUTE_TYPE_REJECT
	default:
		return table.ROUTE_TYPE_NONE
	}
}

func toPolicyDefinition(policies []*api.Policy) []*config.PolicyDefinition {
	l := make([]*config.PolicyDefinition, 0, len(policies))
	for _, p := range policies {
		l = append(l, &config.PolicyDefinition{Name: p.Name})
	}
	return l
}

func (s *server) AddPolicyAssignment(ctx context.Context, r *api.AddPolicyAssignmentRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.AddPolicyAssignment(ctx, r)
}

func (s *server) DeletePolicyAssignment(ctx context.Context, r *api.DeletePolicyAssignmentRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.DeletePolicyAssignment(ctx, r)
}

func (s *server) SetPolicyAssignment(ctx context.Context, r *api.SetPolicyAssignmentRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.SetPolicyAssignment(ctx, r)
}

func (s *server) GetBgp(ctx context.Context, r *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	return s.bgpServer.GetBgp(ctx, r)
}

func newGlobalFromAPIStruct(a *api.Global) *config.Global {
	families := make([]config.AfiSafi, 0, len(a.Families))
	for _, f := range a.Families {
		name := config.IntToAfiSafiTypeMap[int(f)]
		rf, _ := bgp.GetRouteFamily(string(name))
		families = append(families, config.AfiSafi{
			Config: config.AfiSafiConfig{
				AfiSafiName: name,
				Enabled:     true,
			},
			State: config.AfiSafiState{
				AfiSafiName: name,
				Enabled:     true,
				Family:      rf,
			},
		})
	}

	applyPolicy := &config.ApplyPolicy{}
	readApplyPolicyFromAPIStruct(applyPolicy, a.ApplyPolicy)

	global := &config.Global{
		Config: config.GlobalConfig{
			As:               a.Asn,
			RouterId:         a.RouterId,
			Port:             a.ListenPort,
			LocalAddressList: a.ListenAddresses,
		},
		ApplyPolicy: *applyPolicy,
		AfiSafis:    families,
		UseMultiplePaths: config.UseMultiplePaths{
			Config: config.UseMultiplePathsConfig{
				Enabled: a.UseMultiplePaths,
			},
		},
	}
	if a.RouteSelectionOptions != nil {
		global.RouteSelectionOptions = config.RouteSelectionOptions{
			Config: config.RouteSelectionOptionsConfig{
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
		global.DefaultRouteDistance = config.DefaultRouteDistance{
			Config: config.DefaultRouteDistanceConfig{
				ExternalRouteDistance: uint8(a.DefaultRouteDistance.ExternalRouteDistance),
				InternalRouteDistance: uint8(a.DefaultRouteDistance.InternalRouteDistance),
			},
		}
	}
	if a.Confederation != nil {
		global.Confederation = config.Confederation{
			Config: config.ConfederationConfig{
				Enabled:      a.Confederation.Enabled,
				Identifier:   a.Confederation.Identifier,
				MemberAsList: a.Confederation.MemberAsList,
			},
		}
	}
	if a.GracefulRestart != nil {
		global.GracefulRestart = config.GracefulRestart{
			Config: config.GracefulRestartConfig{
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

func (s *server) StartBgp(ctx context.Context, r *api.StartBgpRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.StartBgp(ctx, r)
}

func (s *server) StopBgp(ctx context.Context, r *api.StopBgpRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.StopBgp(ctx, r)
}

func (s *server) GetTable(ctx context.Context, r *api.GetTableRequest) (*api.GetTableResponse, error) {
	return s.bgpServer.GetTable(ctx, r)
}

func (s *server) SetLogLevel(ctx context.Context, r *api.SetLogLevelRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.bgpServer.SetLogLevel(ctx, r)
}

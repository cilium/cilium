// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/internal/pkg/zebra"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// nexthopStateCache stores a map of nexthop IP to metric value. Especially,
// the metric value of math.MaxUint32 means the nexthop is unreachable.
type nexthopStateCache map[string]uint32

func (m nexthopStateCache) applyToPathList(paths []*table.Path) []*table.Path {
	updated := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		if path == nil || path.IsWithdraw {
			continue
		}
		metric, ok := m[path.GetNexthop().String()]
		if !ok {
			continue
		}
		isNexthopInvalid := metric == math.MaxUint32
		med, err := path.GetMed()
		if err == nil && med == metric && path.IsNexthopInvalid == isNexthopInvalid {
			// If the nexthop state of the given path is already up to date,
			// skips this path.
			continue
		}
		newPath := path.Clone(false)
		if isNexthopInvalid {
			newPath.IsNexthopInvalid = true
		} else {
			newPath.IsNexthopInvalid = false
			newPath.SetMed(int64(metric), true)
		}
		updated = append(updated, newPath)
	}
	return updated
}

func (m nexthopStateCache) updateByNexthopUpdate(body *zebra.NexthopUpdateBody) (updated bool) {
	if len(body.Nexthops) == 0 {
		// If NEXTHOP_UPDATE message does not contain any nexthop, the given
		// nexthop is unreachable.
		if _, ok := m[body.Prefix.Prefix.String()]; !ok {
			// Zebra will send an empty NEXTHOP_UPDATE message as the fist
			// response for the NEXTHOP_REGISTER message. Here ignores it.
			return false
		}
		m[body.Prefix.Prefix.String()] = math.MaxUint32 // means unreachable
	} else {
		m[body.Prefix.Prefix.String()] = body.Metric
	}
	return true
}

func (m nexthopStateCache) filterPathToRegister(paths []*table.Path) []*table.Path {
	filteredPaths := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		// Here filters out:
		// - Nil path
		// - Withdrawn path
		// - External path (advertised from Zebra) in order avoid sending back
		// - Unspecified nexthop address
		// - Already registered nexthop
		if path == nil || path.IsWithdraw || path.IsFromExternal() {
			continue
		} else if nexthop := path.GetNexthop(); nexthop.IsUnspecified() {
			continue
		} else if _, ok := m[nexthop.String()]; ok {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func filterOutExternalPath(paths []*table.Path) []*table.Path {
	filteredPaths := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		// Here filters out:
		// - Nil path
		// - External path (advertised from Zebra) in order avoid sending back
		// - Unreachable path because invalidated by Zebra
		if path == nil || path.IsFromExternal() || path.IsNexthopInvalid {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func addLabelToNexthop(path *table.Path, z *zebraClient, msgFlags *zebra.MessageFlag, nexthop *zebra.Nexthop) {
	rf := path.GetRouteFamily()
	if rf == bgp.RF_IPv4_VPN || rf == bgp.RF_IPv6_VPN {
		z.client.SetLabelFlag(msgFlags, nexthop)
		switch rf {
		case bgp.RF_IPv4_VPN:
			for _, label := range path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).Labels.Labels {
				nexthop.LabelNum++
				nexthop.MplsLabels = append(nexthop.MplsLabels, label)
			}
		case bgp.RF_IPv6_VPN:
			for _, label := range path.GetNlri().(*bgp.LabeledVPNIPv6AddrPrefix).Labels.Labels {
				nexthop.LabelNum++
				nexthop.MplsLabels = append(nexthop.MplsLabels, label)
			}
		}
	}
}

func newIPRouteBody(dst []*table.Path, vrfID uint32, z *zebraClient) (body *zebra.IPRouteBody, isWithdraw bool) {
	version := z.client.Version
	paths := filterOutExternalPath(dst)
	if len(paths) == 0 {
		return nil, false
	}
	path := paths[0]

	l := strings.SplitN(path.GetNlri().String(), "/", 2)
	var prefix net.IP
	var nexthop zebra.Nexthop
	nexthops := make([]zebra.Nexthop, 0, len(paths))
	msgFlags := zebra.MessageNexthop
	switch path.GetRouteFamily() {
	case bgp.RF_IPv4_UC:
		prefix = path.GetNlri().(*bgp.IPAddrPrefix).IPAddrPrefixDefault.Prefix.To4()
	case bgp.RF_IPv4_VPN:
		prefix = path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).IPAddrPrefixDefault.Prefix.To4()
	case bgp.RF_IPv6_UC:
		prefix = path.GetNlri().(*bgp.IPv6AddrPrefix).IPAddrPrefixDefault.Prefix.To16()
	case bgp.RF_IPv6_VPN:
		prefix = path.GetNlri().(*bgp.LabeledVPNIPv6AddrPrefix).IPAddrPrefixDefault.Prefix.To16()
	default:
		return nil, false
	}
	nhVrfID := uint32(zebra.DefaultVrf)
	for vrfPath, pathVrfID := range z.pathVrfMap {
		if path.Equal(vrfPath) {
			nhVrfID = pathVrfID
			break
		} else {
			continue
		}
	}
	for _, p := range paths {
		nexthop.Gate = p.GetNexthop()
		nexthop.VrfID = nhVrfID
		if nhVrfID != vrfID {
			addLabelToNexthop(path, z, &msgFlags, &nexthop)
		}
		nexthops = append(nexthops, nexthop)
	}
	plen, _ := strconv.ParseUint(l[1], 10, 8)
	med, err := path.GetMed()
	if err == nil {
		msgFlags |= zebra.MessageMetric.ToEach(version, z.client.Software)
	}
	var flags zebra.Flag
	if path.IsIBGP() {
		flags = zebra.FlagIBGP.ToEach(z.client.Version, z.client.Software) | zebra.FlagAllowRecursion
	} else if path.GetSource().MultihopTtl > 0 {
		flags = zebra.FlagAllowRecursion // 0x01
	}
	return &zebra.IPRouteBody{
		Type:    zebra.RouteBGP,
		Flags:   flags,
		Safi:    zebra.SafiUnicast,
		Message: msgFlags,
		Prefix: zebra.Prefix{
			Prefix:    prefix,
			PrefixLen: uint8(plen),
		},
		Nexthops: nexthops,
		Metric:   med,
	}, path.IsWithdraw
}

func newNexthopRegisterBody(paths []*table.Path, nexthopCache nexthopStateCache) *zebra.NexthopRegisterBody {
	paths = nexthopCache.filterPathToRegister(paths)
	if len(paths) == 0 {
		return nil
	}
	path := paths[0]

	family := path.GetRouteFamily()
	nexthops := make([]*zebra.RegisteredNexthop, 0, len(paths))
	for _, p := range paths {
		nexthop := p.GetNexthop()
		var nh *zebra.RegisteredNexthop
		switch family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN:
			nh = &zebra.RegisteredNexthop{
				Family: syscall.AF_INET,
				Prefix: nexthop.To4(),
			}
		case bgp.RF_IPv6_UC, bgp.RF_IPv6_VPN:
			nh = &zebra.RegisteredNexthop{
				Family: syscall.AF_INET6,
				Prefix: nexthop.To16(),
			}
		default:
			continue
		}
		nexthops = append(nexthops, nh)
	}

	// If no nexthop needs to be registered or unregistered, skips to send
	// message.
	if len(nexthops) == 0 {
		return nil
	}

	return &zebra.NexthopRegisterBody{
		Nexthops: nexthops,
	}
}

func newNexthopUnregisterBody(family uint16, prefix net.IP) *zebra.NexthopRegisterBody {
	return &zebra.NexthopRegisterBody{
		Nexthops: []*zebra.RegisteredNexthop{{
			Family: family,
			Prefix: prefix,
		}},
	}
}

func newPathFromIPRouteMessage(logger log.Logger, m *zebra.Message, version uint8, software zebra.Software) *table.Path {
	header := m.Header
	body := m.Body.(*zebra.IPRouteBody)
	family := body.RouteFamily(logger, version, software)
	isWithdraw := body.IsWithdraw(version, software)

	var nlri bgp.AddrPrefixInterface
	pattr := make([]bgp.PathAttributeInterface, 0)
	origin := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)
	pattr = append(pattr, origin)

	logger.Debug("create path from ip route message",
		log.Fields{
			"Topic":        "Zebra",
			"RouteType":    body.Type.String(),
			"Flag":         body.Flags.String(version, software),
			"Message":      body.Message,
			"Family":       body.Prefix.Family,
			"Prefix":       body.Prefix.Prefix,
			"PrefixLength": body.Prefix.PrefixLen,
			"Nexthop":      body.Nexthops,
			"Metric":       body.Metric,
			"Distance":     body.Distance,
			"Mtu":          body.Mtu,
			"api":          header.Command.String()})

	switch family {
	case bgp.RF_IPv4_UC:
		nlri = bgp.NewIPAddrPrefix(body.Prefix.PrefixLen, body.Prefix.Prefix.String())
		if len(body.Nexthops) > 0 {
			pattr = append(pattr, bgp.NewPathAttributeNextHop(body.Nexthops[0].Gate.String()))
		}
	case bgp.RF_IPv6_UC:
		nlri = bgp.NewIPv6AddrPrefix(body.Prefix.PrefixLen, body.Prefix.Prefix.String())
		nexthop := ""
		if len(body.Nexthops) > 0 {
			nexthop = body.Nexthops[0].Gate.String()
		}
		pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
	default:
		logger.Error("unsupport address family",
			log.Fields{
				"Topic":  "Zebra",
				"Family": family})
		return nil
	}

	med := bgp.NewPathAttributeMultiExitDisc(body.Metric)
	pattr = append(pattr, med)

	path := table.NewPath(nil, nlri, isWithdraw, pattr, time.Now(), false)
	path.SetIsFromExternal(true)
	return path
}

type mplsLabelParameter struct {
	rangeSize     uint32
	maps          map[uint64]*table.Bitmap
	unassignedVrf []*table.Vrf //Vrfs which are not assigned MPLS label
}

type zebraClient struct {
	client       *zebra.Client
	server       *BgpServer
	nexthopCache nexthopStateCache
	pathVrfMap   map[*table.Path]uint32 //vpn paths and nexthop vpn id
	mplsLabel    mplsLabelParameter
	dead         chan struct{}
}

func (z *zebraClient) getPathListWithNexthopUpdate(body *zebra.NexthopUpdateBody) []*table.Path {
	rib := &table.TableManager{
		Tables: make(map[bgp.RouteFamily]*table.Table),
	}

	var rfList []bgp.RouteFamily
	switch body.Prefix.Family {
	case syscall.AF_INET:
		rfList = []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN}
	case syscall.AF_INET6:
		rfList = []bgp.RouteFamily{bgp.RF_IPv6_UC, bgp.RF_IPv6_VPN}
	}

	for _, rf := range rfList {
		tbl, _, err := z.server.getRib("", rf, nil)
		if err != nil {
			z.server.logger.Error("failed to get global rib",
				log.Fields{
					"Topic":  "Zebra",
					"Family": rf.String(),
					"Error":  err})
			continue
		}
		rib.Tables[rf] = tbl
	}

	return rib.GetPathListWithNexthop(table.GLOBAL_RIB_NAME, rfList, body.Prefix.Prefix)
}

func (z *zebraClient) updatePathByNexthopCache(paths []*table.Path) {
	paths = z.nexthopCache.applyToPathList(paths)
	if len(paths) > 0 {
		if err := z.server.updatePath("", paths); err != nil {
			z.server.logger.Error("failed to update nexthop reachability",
				log.Fields{
					"Topic":    "Zebra",
					"PathList": paths})
		}
	}
}

func (z *zebraClient) loop() {
	w := z.server.watch([]watchOption{
		watchBestPath(true),
		watchPostUpdate(true, ""),
	}...)
	defer w.Stop()

	for {
		select {
		case <-z.dead:
			return
		case msg := <-z.client.Receive():
			if msg == nil {
				break
			}
			switch body := msg.Body.(type) {
			case *zebra.IPRouteBody:
				if path := newPathFromIPRouteMessage(z.server.logger, msg, z.client.Version, z.client.Software); path != nil {
					if err := z.server.addPathList("", []*table.Path{path}); err != nil {
						z.server.logger.Error("failed to add path from zebra",
							log.Fields{
								"Topic": "Zebra",
								"Path":  path,
								"Error": err})
					}
				}
			case *zebra.NexthopUpdateBody:
				if updated := z.nexthopCache.updateByNexthopUpdate(body); !updated {
					continue
				}
				paths := z.getPathListWithNexthopUpdate(body)
				if len(paths) == 0 {
					// If there is no path bound for the given nexthop, send
					// NEXTHOP_UNREGISTER message.
					z.client.SendNexthopRegister(msg.Header.VrfID, newNexthopUnregisterBody(uint16(body.Prefix.Family), body.Prefix.Prefix), true)
					delete(z.nexthopCache, body.Prefix.Prefix.String())
				}
				z.updatePathByNexthopCache(paths)
			case *zebra.GetLabelChunkBody:
				z.server.logger.Debug("zebra GetLabelChunkBody is received",
					log.Fields{
						"Topic": "Zebra",
						"Start": body.Start,
						"End":   body.End})
				startEnd := uint64(body.Start)<<32 | uint64(body.End)
				z.mplsLabel.maps[startEnd] = table.NewBitmap(int(body.End - body.Start + 1))
				for _, vrf := range z.mplsLabel.unassignedVrf {
					if err := z.assignAndSendVrfMplsLabel(vrf); err != nil {
						z.server.logger.Error("zebra failed to assign and send vrf mpls label",
							log.Fields{
								"Topic": "Zebra",
								"Error": err})
					}
				}
				z.mplsLabel.unassignedVrf = nil
			}
		case ev := <-w.Event():
			switch msg := ev.(type) {
			case *watchEventBestPath:
				if table.UseMultiplePaths.Enabled {
					for _, paths := range msg.MultiPathList {
						z.updatePathByNexthopCache(paths)
						for i := range msg.Vrf {
							if body, isWithdraw := newIPRouteBody(paths, i, z); body != nil {
								z.client.SendIPRoute(i, body, isWithdraw)
							}
							if body := newNexthopRegisterBody(paths, z.nexthopCache); body != nil {
								z.client.SendNexthopRegister(i, body, false)
							}
						}
					}
				} else {
					z.updatePathByNexthopCache(msg.PathList)
					for _, path := range msg.PathList {
						for i := range msg.Vrf {
							if body, isWithdraw := newIPRouteBody([]*table.Path{path}, i, z); body != nil {
								err := z.client.SendIPRoute(i, body, isWithdraw)
								if err != nil {
									continue
								}
							}
							if body := newNexthopRegisterBody([]*table.Path{path}, z.nexthopCache); body != nil {
								z.client.SendNexthopRegister(i, body, false)
							}
						}
					}
				}
			case *watchEventUpdate:
				if body := newNexthopRegisterBody(msg.PathList, z.nexthopCache); body != nil {
					vrfID := uint32(0)
					for _, vrf := range z.server.listVrf() {
						if vrf.Name == msg.Neighbor.Config.Vrf {
							vrfID = uint32(vrf.Id)
						}
					}
					z.client.SendNexthopRegister(vrfID, body, false)
				}
			}
		}
	}
}

func newZebraClient(s *BgpServer, url string, protos []string, version uint8, nhtEnable bool, nhtDelay uint8, mplsLabelRangeSize uint32, software zebra.Software) (*zebraClient, error) {
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return nil, fmt.Errorf("unsupported url: %s", url)
	}
	var cli *zebra.Client
	var err error
	var usingVersion uint8
	var zapivers [zebra.MaxZapiVer - zebra.MinZapiVer + 1]uint8
	zapivers[0] = version
	for elem, ver := 1, zebra.MinZapiVer; elem < len(zapivers) && ver <= zebra.MaxZapiVer; elem++ {
		if version == ver && ver < zebra.MaxZapiVer {
			ver++
		}
		zapivers[elem] = ver
		ver++
	}
	for elem, ver := range zapivers {
		cli, err = zebra.NewClient(s.logger, l[0], l[1], zebra.RouteBGP, ver, software, mplsLabelRangeSize)
		if cli != nil && err == nil {
			usingVersion = ver
			break
		}
		// Retry with another Zebra message version
		s.logger.Warn("cannot connect to Zebra with message version",
			log.Fields{
				"Topic":   "Zebra",
				"Version": ver})
		if elem < len(zapivers)-1 {
			s.logger.Warn("going to retry another version",
				log.Fields{
					"Topic":   "Zebra",
					"Version": zapivers[elem+1]})
		}
	}
	if cli == nil || err != nil {
		return nil, err
	}
	s.logger.Info("success to connect to Zebra",
		log.Fields{
			"Topic":   "Zebra",
			"Version": usingVersion})

	// Note: HELLO/ROUTER_ID_ADD messages are automatically sent to negotiate
	// the Zebra message version in zebra.NewClient().
	// cli.SendHello()
	// cli.SendRouterIDAdd()
	cli.SendInterfaceAdd()
	for _, typ := range protos {
		t, err := zebra.RouteTypeFromString(typ, version, software)
		if err != nil {
			return nil, err
		}
		cli.SendRedistribute(t, zebra.DefaultVrf)
	}
	w := &zebraClient{
		client:       cli,
		server:       s,
		nexthopCache: make(nexthopStateCache),
		pathVrfMap:   make(map[*table.Path]uint32),
		mplsLabel: mplsLabelParameter{
			rangeSize: mplsLabelRangeSize,
			maps:      make(map[uint64]*table.Bitmap),
		},
		dead: make(chan struct{}),
	}
	go w.loop()
	if mplsLabelRangeSize > 0 && cli.SupportMpls() {
		if err = cli.SendGetLabelChunk(&zebra.GetLabelChunkBody{ChunkSize: mplsLabelRangeSize}); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func (z *zebraClient) assignMplsLabel() (uint32, error) {
	if z.mplsLabel.maps == nil {
		return 0, nil
	}
	var label uint32
	for startEnd, bitmap := range z.mplsLabel.maps {
		start := uint32(startEnd >> 32)
		end := uint32(startEnd & 0xffffffff)
		l, err := bitmap.FindandSetZeroBit()
		if err == nil && start+uint32(l) <= end {
			label = start + uint32(l)
			break
		}
	}
	if label == 0 {
		return 0, fmt.Errorf("failed to assign new MPLS label")
	}
	return label, nil
}

func (z *zebraClient) assignAndSendVrfMplsLabel(vrf *table.Vrf) error {
	var err error
	if vrf.MplsLabel, err = z.assignMplsLabel(); vrf.MplsLabel > 0 { // success
		if err = z.client.SendVrfLabel(vrf.MplsLabel, vrf.Id); err != nil {
			return err
		}
	} else if vrf.MplsLabel == 0 { // GetLabelChunk is not performed
		z.mplsLabel.unassignedVrf = append(z.mplsLabel.unassignedVrf, vrf)
	}
	return err
}

func (z *zebraClient) releaseMplsLabel(label uint32) {
	if z.mplsLabel.maps == nil {
		return
	}
	for startEnd, bitmap := range z.mplsLabel.maps {
		start := uint32(startEnd >> 32)
		end := uint32(startEnd & 0xffffffff)
		if start <= label && label <= end {
			bitmap.Unflag(uint(label - start))
			return
		}
	}
}

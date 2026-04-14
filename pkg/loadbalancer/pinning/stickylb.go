// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pinning

import (
	"hash/fnv"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/pkg/loadbalancer/maps"
)

func calcNodeIndex(ipAddr netip.Addr, nodeCount uint32) int {
	h := fnv.New32a()
	h.Write(ipAddr.AsSlice())

	return int(h.Sum32() % nodeCount)
}

func rebalanceServices(
	currentPinningMap pinningMap,
	services []netip.Addr,
	nodes []netip.Addr,
	localNodeIp netip.Addr,
) (pinningMap, error) {
	newPinningMap := pinningMap{}
	rebalanceServices := []netip.Addr{}

	for _, svcip := range services {
		processed := false

		// check previous mapping
		for svcipPrev, nodeip := range currentPinningMap {
			if svcipPrev.ServiceIP.Addr() != svcip || nodeip.NodeIP.Addr() == localNodeIp {
				continue
			}

			processed = true

			if !slices.Contains(nodes, nodeip.NodeIP.Addr()) {
				rebalanceServices = append(rebalanceServices, svcip)
			} else {
				newPinningMap[maps.LbPinning4Key{ServiceIP: iPv4FromAddr(svcip)}] = nodeip
			}
		}

		if !processed {
			rebalanceServices = append(rebalanceServices, svcip)
		}
	}

	nodesCount := uint32(len(nodes))

	slices.SortFunc(nodes, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	for _, ip := range rebalanceServices {
		i := calcNodeIndex(ip, nodesCount)

		newPinningMap[maps.LbPinning4Key{ServiceIP: iPv4FromAddr(ip)}] = maps.LbPinning4Value{NodeIP: iPv4FromAddr(nodes[i])}
	}

	return newPinningMap, nil
}

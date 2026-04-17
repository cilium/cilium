// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pinning

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/k8s/resource"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/types"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

func eventDone[T k8sRuntime.Object](event resource.Event[T], err error) error {
	event.Done(err)

	return err
}

func DumpPinningMap(lBMaps lbmaps.LBMaps) (PinningMap, error) {
	m := PinningMap{}

	if err := lBMaps.DumpPinning4(func(lpk *lbmaps.LbPinning4Key, lpv *lbmaps.LbPinning4Value) {
		m[*lpk] = *lpv
	}); err != nil {
		return nil, err
	}

	return m, nil
}

func iPv4FromAddr(ip netip.Addr) types.IPv4 {
	ipv4 := types.IPv4{}
	ipv4.FromAddr(ip)

	return ipv4
}

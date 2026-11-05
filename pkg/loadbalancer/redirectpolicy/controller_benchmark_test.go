// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"fmt"
	"testing"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lrpTypes "github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy/types"
)

// BenchmarkShouldRedirectFrontend measures the worst-case named-port lookup,
// where only the final pod provides a backend compatible with the frontend.
func BenchmarkShouldRedirectFrontend(b *testing.B) {
	for _, podCount := range []int{10, 10_000, 50_000} {
		b.Run(fmt.Sprintf("pods=%d", podCount), func(b *testing.B) {
			lrp, frontend, pods := benchmarkFrontendRedirect(podCount)

			// Verify that no earlier pod satisfies the lookup. This ensures each
			// benchmark operation scans the complete slice before matching the
			// TCP/53 port on the final pod.
			if shouldRedirectFrontend(nil, lrp, frontend, pods[:len(pods)-1]) {
				b.Fatal("frontend unexpectedly matched before the final pod")
			}
			if !shouldRedirectFrontend(nil, lrp, frontend, pods) {
				b.Fatal("frontend did not match the final pod")
			}

			b.ReportAllocs()
			b.ResetTimer()
			var redirected bool
			for b.Loop() {
				redirected = shouldRedirectFrontend(nil, lrp, frontend, pods)
			}
			if !redirected {
				b.Fatal("frontend did not redirect")
			}
			b.ReportMetric(float64(podCount)*float64(b.N)/b.Elapsed().Seconds(), "pods/sec")
		})
	}
}

func benchmarkFrontendRedirect(podCount int) (*LocalRedirectPolicy, *loadbalancer.Frontend, []podInfo) {
	const (
		dnsUDPPortName = loadbalancer.FEPortName("dns")
		dnsTCPPortName = loadbalancer.FEPortName("dns-tcp")
	)

	dnsUDPPort := bePortInfo{l4Addr: loadbalancer.NewL4Addr(loadbalancer.UDP, 53), name: dnsUDPPortName}
	dnsTCPPort := bePortInfo{l4Addr: loadbalancer.NewL4Addr(loadbalancer.TCP, 53), name: dnsTCPPortName}
	lrp := &LocalRedirectPolicy{
		FrontendType: lrpTypes.FrontendTypeServiceAll,
		BackendPorts: []bePortInfo{dnsUDPPort, dnsTCPPort},
		BackendPortsByPortName: map[loadbalancer.FEPortName]bePortInfo{
			dnsUDPPortName: dnsUDPPort,
			dnsTCPPortName: dnsTCPPort,
		},
	}

	podIP := cmtypes.MustParseAddrCluster("10.0.0.2")
	dnsUDPAddr := podAddr{
		L3n4Addr: loadbalancer.NewL3n4Addr(loadbalancer.UDP, podIP, 53, loadbalancer.ScopeExternal),
		portName: string(dnsUDPPortName),
	}
	dnsTCPAddr := podAddr{
		L3n4Addr: loadbalancer.NewL3n4Addr(loadbalancer.TCP, podIP, 53, loadbalancer.ScopeExternal),
		portName: string(dnsTCPPortName),
	}

	pods := make([]podInfo, podCount)
	for i := range pods {
		pods[i].addrs = []podAddr{dnsUDPAddr}
	}
	// Only the final pod exposes the TCP port matched by the frontend.
	pods[len(pods)-1].addrs = append(pods[len(pods)-1].addrs, dnsTCPAddr)

	frontend := &loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			Address:  loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.MustParseAddrCluster("10.96.0.10"), 53, loadbalancer.ScopeExternal),
			PortName: dnsTCPPortName,
		},
	}
	return lrp, frontend, pods
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicestats

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

type fakeReader map[string]Stats

func (f fakeReader) Stats(iface string) (Stats, error) {
	return f[iface], nil
}

type fakeDevices []string

func (f fakeDevices) Names() []string { return f }

func TestCollector(t *testing.T) {
	reader := fakeReader{
		"eth0": Stats{RxPackets: 10, TxPackets: 20, RxBytes: 30, TxBytes: 40},
	}
	c := newCollector(reader, fakeDevices{"eth0"})

	want := `
# HELP cilium_device_bytes_total Total number of bytes seen on a Cilium-managed device, tagged by ingress/egress direction
# TYPE cilium_device_bytes_total counter
cilium_device_bytes_total{device="eth0",direction="EGRESS"} 40
cilium_device_bytes_total{device="eth0",direction="INGRESS"} 30
# HELP cilium_device_packets_total Total number of packets seen on a Cilium-managed device, tagged by ingress/egress direction
# TYPE cilium_device_packets_total counter
cilium_device_packets_total{device="eth0",direction="EGRESS"} 20
cilium_device_packets_total{device="eth0",direction="INGRESS"} 10
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}

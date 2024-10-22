// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"

	"github.com/stretchr/testify/assert"
)

func Test_topk(t *testing.T) {
	top5 := newTopK[key4](5)
	for i := byte(0); i < 10; i++ {
		ip := types.IPv4{10, 0, 0, i}
		k := key4{
			DestAddr: ip,
		}
		top5.Push(k, int(i))
	}
	out := []int{}
	top5.popForEach(func(key key4, count, ith int) { out = append(out, count) })
	assert.Equal(t, []int{5, 6, 7, 8, 9}, out)
}

func Test_countNat(t *testing.T) {
	testutils.PrivilegedTest(t)

	ip4Map := nat.NewMap("test_nat_map_ip4", nat.IPv4, 262144)
	err := ip4Map.OpenOrCreate()
	assert.NoError(t, err)
	ip6Map := nat.NewMap("test_nat_map_ip6", nat.IPv6, 262144)
	err = ip6Map.OpenOrCreate()
	assert.NoError(t, err)
	t.Cleanup(func() {
		ip4Map.UnpinIfExists()
		ip6Map.UnpinIfExists()
	})

	for addr := byte(0); addr < 20; addr++ {
		for i := uint16(0); i < uint16(addr); i++ {
			ip := types.IPv4{10, 0, 0, addr}
			mapKey := &nat.NatKey4{}
			mapKey.TupleKey4.SourceAddr = ip
			mapKey.TupleKey4.DestAddr = [4]byte{}
			mapKey.TupleKey4.DestPort = 9000 + i
			// We're enumerating our buckets by the addr value, as the source-port is part of our
			// connection tuple: {proto, egress_ip, endpoint_ip, endpoint_port} we pin this to the same
			// value as the final octet of our IP to make things simple (similar for ipv6).
			mapKey.TupleKey4.SourcePort = 8000 + uint16(addr) // this becomes the remote port.
			mapKey.Flags = tuple.TUPLE_F_IN
			mapKey.NextHeader = u8proto.TCP

			ip6 := types.IPv6{}
			ip6[15] = addr
			mapKey6 := &nat.NatKey6{}
			mapKey6.TupleKey6.SourceAddr = ip6
			mapKey6.TupleKey6.DestAddr = [16]byte{}
			mapKey6.TupleKey6.DestPort = 9000 + i
			mapKey6.TupleKey6.SourcePort = 8000 + uint16(addr) // this becomes the remote port
			mapKey6.Flags = tuple.TUPLE_F_IN
			mapKey6.NextHeader = u8proto.TCP

			err = ip4Map.Update(mapKey.ToNetwork(), &nat.NatEntry4{})
			assert.NoError(t, err)
			mapKeyUdp := *mapKey
			mapKeyUdp.NextHeader = u8proto.UDP
			// UDP counts as its own bucket, but cap the number of unique sports to 9, so it's never in topk.
			mapKeyUdp.DestPort = 9000 + (i % 9)
			err = ip4Map.Update(mapKey.ToNetwork(), &nat.NatEntry4{})
			assert.NoError(t, err)

			mapKey.TupleKey4.SourceAddr = ip
			mapKey.TupleKey4.DestAddr = [4]byte{}
			mapKey.Flags = tuple.TUPLE_F_OUT
			err = ip4Map.Update(mapKey.ToNetwork(), &nat.NatEntry4{})
			assert.NoError(t, err)

			err = ip6Map.Update(mapKey6.ToNetwork(), &nat.NatEntry6{})
			assert.NoError(t, err)
			mapKey6.TupleKey6.SourceAddr = ip6
			mapKey6.TupleKey6.DestAddr = [16]byte{}
			mapKey6.Flags = tuple.TUPLE_F_OUT
			err = ip6Map.Update(mapKey6.ToNetwork(), &nat.NatEntry6{})
			assert.NoError(t, err)
		}
	}

	ms := make(fakeMetrics)
	h := hive.New(
		cell.Provide(newTables),
		cell.Provide(func(jg job.Registry) job.Group {
			return jg.NewGroup(nil)
		}),
		cell.Provide(func() (promise.Promise[nat.NatMap4], promise.Promise[nat.NatMap6], Config, natMetrics) {
			r4, p4 := promise.New[nat.NatMap4]()
			r6, p6 := promise.New[nat.NatMap6]()
			r4.Resolve(ip4Map)
			r6.Resolve(ip6Map)
			return p4, p6, Config{NATMapStatInterval: 30 * time.Second, NatMapStatKStoredEntries: 10}, ms
		}),
		cell.Provide(newStats),
		cell.Invoke(func(s *Stats, lc cell.Lifecycle) {
			s.natMap4 = ip4Map
			s.natMap6 = ip6Map
			assert.NoError(t, s.countNat(context.Background()))
			it := s.table.All(s.db.ReadTxn())
			freq := map[string]int{}
			for o := range it {
				switch o.Type {
				case "ipv4":
					assert.Equal(t, fmt.Sprintf("10.0.0.%d", o.Count), o.EndpointIP)
				case "ipv6":
					assert.Equal(t, fmt.Sprintf("::%x", o.Count), o.EndpointIP)
				default:
					assert.FailNow(t, "unexpected family type")
				}
				assert.Equal(t, 8019-(o.Nth-1), int(o.RemotePort))
				freq[o.Type]++
			}
			assert.Equal(t, 19, ms[nat.IPv4.String()])
			assert.Equal(t, 19, ms[nat.IPv6.String()])
			assert.Equal(t, map[string]int{"ipv4": 10, "ipv6": 10}, freq)
		}),
	)
	assert.NoError(t, h.Populate(hivetest.Logger(t)))
}

type fakeMetrics map[string]int

func (m fakeMetrics) updateLocalPorts(family nat.IPFamily, count, maxPorts int) {
	m[family.String()] = count
}

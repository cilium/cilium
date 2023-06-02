// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/byteorder"
)

func (s *BPFTestSuite) TestExtractCommonName(c *C) {
	c.Assert(extractCommonName("cilium_calls_1157"), Equals, "calls")
	c.Assert(extractCommonName("cilium_calls_netdev_ns_1"), Equals, "calls")
	c.Assert(extractCommonName("cilium_calls_overlay_2"), Equals, "calls")
	c.Assert(extractCommonName("cilium_ct4_global"), Equals, "ct4_global")
	c.Assert(extractCommonName("cilium_ct_any4_global"), Equals, "ct_any4_global")
	c.Assert(extractCommonName("cilium_events"), Equals, "events")
	c.Assert(extractCommonName("cilium_ipcache"), Equals, "ipcache")
	c.Assert(extractCommonName("cilium_lb4_reverse_nat"), Equals, "lb4_reverse_nat")
	c.Assert(extractCommonName("cilium_lb4_rr_seq"), Equals, "lb4_rr_seq")
	c.Assert(extractCommonName("cilium_lb4_services"), Equals, "lb4_services")
	c.Assert(extractCommonName("cilium_lxc"), Equals, "lxc")
	c.Assert(extractCommonName("cilium_metrics"), Equals, "metrics")
	c.Assert(extractCommonName("cilium_policy"), Equals, "policy")
	c.Assert(extractCommonName("cilium_policy_1157"), Equals, "policy")
	c.Assert(extractCommonName("cilium_policy_reserved_1"), Equals, "policy")
	c.Assert(extractCommonName("cilium_proxy4"), Equals, "proxy4")
	c.Assert(extractCommonName("cilium_tunnel_map"), Equals, "tunnel_map")
}

type BenchKey struct {
	Key uint32
}
type BenchValue struct {
	Value uint32
}

func (k *BenchKey) String() string            { return fmt.Sprintf("key=%d", k.Key) }
func (k *BenchKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *BenchKey) NewValue() MapValue        { return &BenchValue{} }
func (k *BenchKey) DeepCopyMapKey() MapKey    { return &BenchKey{k.Key} }

func (v *BenchValue) String() string              { return fmt.Sprintf("value=%d", v.Value) }
func (v *BenchValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *BenchValue) DeepCopyMapValue() MapValue  { return &BenchValue{v.Value} }

func (s *BPFTestSuite) BenchmarkConvertKeyValue(c *C) {
	bk := []byte{0x21, 0x09, 0x40, 0xff}
	bv := []byte{0x18, 0x2d, 0x44, 0x54}
	k := &BenchKey{}
	v := &BenchValue{}
	wantK := uint32(0xff400921)
	wantV := uint32(0x54442d18)
	if byteorder.Native == binary.BigEndian {
		wantK = 0x210940ff
		wantV = 0x182d5554
	}
	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		ConvertKeyValue(bk, bv, k, v)
	}
	c.StopTimer()
	if c.N > 0 {
		c.Assert(k.Key, Equals, wantK)
		c.Assert(v.Value, Equals, wantV)
	}
}

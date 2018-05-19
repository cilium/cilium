// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datametrics

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger

const (
	// MapName for metrics map.
	MapName = "cilium_metrics"
	// MaxEntries is the maximum number of keys that can be present in the
	// Metrics Map.
	MaxEntries = 65536
)

var direction = map[uint8]string{
	0: "INGRESS",
	1: "EGRESS",
}

var dropForwardReason = map[uint8]string{
	0:   "FORWARD",
	130: "DROP_INVALID_SMAC",
	131: "DROP_INVALID_DMAC",
	132: "DROP_INVALID_SIP",
	133: "DROP_POLICY",
	134: "DROP_INVALID",
	135: "DROP_CT_INVALID_HDR",
	136: "DROP_CT_MISSING_ACK",
	137: "DROP_CT_UNKNOWN_PROTO",
	138: "DROP_CT_CANT_CREATE",
	139: "DROP_UNKNOWN_L3",
	140: "DROP_MISSED_TAIL_CALL",
	141: "DROP_WRITE_ERROR",
	142: "DROP_UNKNOWN_L4",
	143: "DROP_UNKNOWN_ICMP_CODE",
	144: "DROP_UNKNOWN_ICMP_TYPE",
	145: "DROP_UNKNOWN_ICMP6_CODE",
	146: "DROP_UNKNOWN_ICMP6_TYPE",
	147: "DROP_NO_TUNNEL_KEY",
	148: "DROP_NO_TUNNEL_OPT",
	149: "DROP_INVALID_GENEVE",
	150: "DROP_UNKNOWN_TARGET",
	151: "DROP_NON_LOCAL",
	152: "DROP_NO_LXC",
	153: "DROP_CSUM_L3",
	154: "DROP_CSUM_L4",
	155: "DROP_CT_CREATE_FAILED",
	156: "DROP_INVALID_EXTHDR",
	157: "DROP_FRAG_NOSUPPORT",
	158: "DROP_NO_SERVICE",
	159: "DROP_POLICY_L4",
	160: "DROP_NO_TUNNEL_ENDPOINT",
	161: "DROP_PROXYMAP_CREATE_FAILED",
	162: "DROP_POLICY_CIDR",
}

// Key must be in sync with struct metrics_key in <bpf/lib/common.h>
type Key struct {
	reason   uint8
	dir      uint8
	reserved [3]uint16
}

// Value must be in sync with struct metrics_value in <bpf/lib/common.h>
type Value struct {
	count uint64
	bytes uint64
}

// String converts the key into a human readable string format
func (k Key) String() string {
	return fmt.Sprintf("reason:%d dir:%d", k.reason, k.dir)
}

// String converts the key into a human readable string format
func (k Key) GetDirection() string {
	//TODO confirm if direction is valid?
	return dropForwardReason[k.dir]
}

// String converts the key into a human readable string format
func (k Key) IsDrop() bool {
	//TODO confirm if direction is valid?
	return k.reason != 0
}

// String converts the reason into a human readable string format
func (k Key) GetDropReason() string {
	//TODO confirm if reason is valid?
	return dropForwardReason[k.reason]
}

// String converts the request count into a human readable string format
func (v Value) GetCount() float64 {
	//TODO confirm if reason is valid?
	return float64(v.count)
}

// String converts the request bytes into a human readable string format
func (v Value) GetBytes() float64 {
	//TODO confirm if reason is valid?
	return float64(v.count)
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k Key) NewValue() bpf.MapValue { return &Value{} }

// String converts the value into a human readable string format
func (v *Value) String() string {
	return fmt.Sprintf("count:%d bytes:%d", v.count, v.bytes)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

var (
	// Metrics is a mapping of all packet drops and forwards associated with
	// the node on ingress/egress direction
	Metrics = bpf.NewMap(
		MapName,
		bpf.BPF_MAP_TYPE_HASH,
		int(unsafe.Sizeof(Value{})),
		int(unsafe.Sizeof(Value{})),
		MaxEntries,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := Key{}, Value{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}
			return k, &v, nil
		})
)

func init() {
	err := bpf.OpenAfterMount(Metrics)
	if err != nil {
		log.WithError(err).Error("unable to open metrics map")
	}
}

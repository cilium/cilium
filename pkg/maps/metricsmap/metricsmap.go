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

package metricsmap

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
func (k *Key) String() string {
	return fmt.Sprintf("reason:%d dir:%d", k.reason, k.dir)
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// String converts the value into a human readable string format
func (v *Value) String() string {
	return fmt.Sprintf("count:%d bytes:%d", v.count, v.bytes)
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *Key) NewValue() bpf.MapValue { return &Value{} }

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
			return &k, &v, nil
		})
)

func init() {
	err := bpf.OpenAfterMount(Metrics)
	if err != nil {
		log.WithError(err).Error("unable to open metrics map")
	}
}

// Copyright 2019 Authors of Cilium
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

// +build linux,!privileged_tests

package bpf

import (
	"fmt"
	"unsafe"

	. "gopkg.in/check.v1"
)

type TestKey struct {
	Key uint32
}
type TestValue struct {
	Value uint32
}

func (k *TestKey) String() string            { return fmt.Sprintf("key=%d", k.Key) }
func (k *TestKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *TestKey) NewValue() MapValue        { return &TestValue{} }
func (k *TestKey) DeepCopyMapKey() MapKey    { return &TestKey{k.Key} }

func (v *TestValue) String() string              { return fmt.Sprintf("value=%d", v.Value) }
func (v *TestValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *TestValue) DeepCopyMapValue() MapValue  { return &TestValue{v.Value} }

func (s *BPFTestSuite) BenchmarkAddEntry(c *C) {
	hm := &HistoryManager{}
	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		hm.addEntry(&TestKey{Key: 1}, &TestValue{Value: 1}, OK,
			fmt.Errorf("error"))
	}
}

func (s *BPFTestSuite) BenchmarkAddDeleteAllEntry(c *C) {
	hm := &HistoryManager{}
	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		hm.addDeleteAllEntry(fmt.Errorf("error"))
	}
}

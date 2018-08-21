// Copyright 2017 Authors of Cilium
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

package syncbytes

import (
	"bytes"

	"github.com/cilium/cilium/pkg/lock"
)

// Buffer is a golang's buffer wrapper that can be used concurrently.
type Buffer struct {
	b bytes.Buffer
	m lock.RWMutex
}

// Read calls the Read method for the internal Buffer in a thread safe
// environment.
func (b *Buffer) Read(p []byte) (n int, err error) {
	b.m.RLock()
	defer b.m.RUnlock()
	return b.b.Read(p)
}

// Write calls the Write method for the internal Buffer in a thread safe
// environment.
func (b *Buffer) Write(p []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Write(p)
}

// Bytes returns a copy of the internal bytes Buffer that can be modified by the
// caller.
func (b *Buffer) Bytes() []byte {
	b.m.RLock()
	bcpy := make([]byte, len(b.b.Bytes()))
	copy(bcpy, b.b.Bytes())
	b.m.RUnlock()
	return bcpy
}

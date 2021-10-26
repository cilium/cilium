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

// +build !privileged_tests

package endpoint

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/linux"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	. "gopkg.in/check.v1"
)

func (s *EndpointSuite) TestWriteInformationalComments(c *C) {
	e := NewEndpointWithState(s, &FakeEndpointProxy{}, testidentity.NewFakeIdentityAllocator(nil), 100, StateWaitingForIdentity)

	var f bytes.Buffer
	err := e.writeInformationalComments(&f)
	c.Assert(err, IsNil)
}

type writeFunc func(io.Writer) error

func BenchmarkWriteHeaderfile(b *testing.B) {
	e := NewEndpointWithState(&suite, &FakeEndpointProxy{}, testidentity.NewFakeIdentityAllocator(nil), 100, StateWaitingForIdentity)
	dp := linux.NewDatapath(linux.DatapathConfiguration{}, nil, nil)

	targetComments := func(w io.Writer) error {
		return e.writeInformationalComments(w)
	}
	targetConfig := func(w io.Writer) error {
		return dp.WriteEndpointConfig(w, e)
	}

	var buf bytes.Buffer
	file, err := os.CreateTemp("", "cilium_ep_bench_")
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()

	benchmarks := []struct {
		name   string
		output io.Writer
		write  writeFunc
	}{
		{"in-memory-info", &buf, targetComments},
		{"in-memory-cfg", &buf, targetConfig},
		{"to-disk-info", file, targetComments},
		{"to-disk-cfg", file, targetConfig},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if err := bm.write(bm.output); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

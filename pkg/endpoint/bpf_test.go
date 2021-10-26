// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

//go:build !privileged_tests && integration_tests
// +build !privileged_tests,integration_tests

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
	e := NewEndpointWithState(s, &FakeEndpointProxy{}, &testidentity.FakeIdentityAllocator{}, 100, StateWaitingForIdentity)

	var f bytes.Buffer
	err := e.writeInformationalComments(&f)
	c.Assert(err, IsNil)
}

type writeFunc func(io.Writer) error

func BenchmarkWriteHeaderfile(b *testing.B) {
	e := NewEndpointWithState(&suite, &FakeEndpointProxy{}, &testidentity.FakeIdentityAllocator{}, 100, StateWaitingForIdentity)
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

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

func TestWriteInformationalComments(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointSuite(t)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	p := EndpointParams{
		Logger:           logger,
		EPBuildQueue:     &MockEndpointBuildQueue{},
		Orchestrator:     s.orchestrator,
		PolicyRepo:       s.repo,
		IdentityManager:  identitymanager.NewIDManager(logger),
		NamedPortsGetter: testipcache.NewMockIPCache(),
		IPSecConfig:      fakeipsec.Config{},
		WgConfig:         fakewireguard.Config{},
		CTMapGC:          ctmap.NewFakeGCRunner(),
		Allocator:        testidentity.NewMockIdentityAllocator(nil),
	}
	e, err := NewEndpointFromChangeModel(p, nil, nil, model, nil)
	require.NoError(t, err)

	e.Start(uint16(model.ID))
	t.Cleanup(e.Stop)

	var f bytes.Buffer
	err = e.writeInformationalComments(&f)
	require.NoError(t, err)
}

type writeFunc func(io.Writer) error

func BenchmarkWriteHeaderfile(b *testing.B) {
	logger := hivetest.Logger(b)
	testutils.IntegrationTest(b)

	s := setupEndpointSuite(b)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	p := EndpointParams{
		Logger:           logger,
		EPBuildQueue:     &MockEndpointBuildQueue{},
		Orchestrator:     s.orchestrator,
		PolicyRepo:       s.repo,
		IdentityManager:  identitymanager.NewIDManager(logger),
		NamedPortsGetter: testipcache.NewMockIPCache(),
		IPSecConfig:      fakeipsec.Config{},
		WgConfig:         fakewireguard.Config{},
		CTMapGC:          ctmap.NewFakeGCRunner(),
		Allocator:        testidentity.NewMockIdentityAllocator(nil),
	}
	e, err := NewEndpointFromChangeModel(p, nil, nil, model, nil)
	require.NoError(b, err)

	e.Start(uint16(model.ID))
	b.Cleanup(e.Stop)

	configWriter := &linuxConfig.HeaderfileWriter{}

	targetComments := func(w io.Writer) error {
		return e.writeInformationalComments(w)
	}
	targetConfig := func(w io.Writer) error {
		return configWriter.WriteEndpointConfig(w, e)
	}

	var buf bytes.Buffer
	memoryBacked := func() (io.Writer, func() error) {
		return &buf, func() error { buf.Reset(); return nil }
	}

	f, err := os.CreateTemp("", "cilium_ep_bench_")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	fileBacked := func() (io.Writer, func() error) {
		return f, func() error {
			_, err := f.Seek(0, io.SeekStart)
			return err
		}
	}

	benchmarks := []struct {
		name       string
		outputFunc func() (io.Writer, func() error)
		write      writeFunc
	}{
		{"in-memory-info", memoryBacked, targetComments},
		{"in-memory-cfg", memoryBacked, targetConfig},
		{"to-disk-info", fileBacked, targetComments},
		{"to-disk-cfg", fileBacked, targetConfig},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			output, reset := bm.outputFunc()
			// Prewarn caches, buffers and the golang JSON marshaller. Since we use b.Loop() this will not be counted
			if err := bm.write(output); err != nil {
				b.Fatal(err)
			}

			for b.Loop() {
				// Reset buffer/file offset to avoid allocating unbounded amounts of memory or disk
				if err := reset(); err != nil {
					b.Fatal(err)
				}
				if err := bm.write(output); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

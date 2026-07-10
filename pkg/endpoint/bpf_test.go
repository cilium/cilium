// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestWriteInformationalComments(t *testing.T) {
	s := setupEndpointSuite(t)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	p := createEndpointParams(t, s.orchestrator, s.repo, s.fetcher)
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, model, nil)
	require.NoError(t, err)

	e.Start(uint16(model.ID))
	t.Cleanup(e.Stop)

	var f bytes.Buffer
	err = e.writeInformationalComments(&f)
	require.NoError(t, err)
}

type writeFunc func(io.Writer) error

func BenchmarkWriteHeaderfile(b *testing.B) {
	testutils.IntegrationTest(b)

	s := setupEndpointSuite(b)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	p := createEndpointParams(b, s.orchestrator, s.repo, s.fetcher)
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, model, nil)
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

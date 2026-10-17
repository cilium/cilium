// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/config"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	dummyNodeCfg = config.Config{}
)

// TestHashDatapath is done in this package just for easy access to dummy
// configuration objects.
func TestHashDatapath(t *testing.T) {
	// Error from ConfigWriter is forwarded.
	_, err := hashDatapath(fakeConfigWriter{}, nil, nil)
	require.Error(t, err)

	// Ensure we get different hashes when config is changed
	a, err := hashDatapath(fakeConfigWriter("a"), &dummyNodeCfg, nil)
	require.NoError(t, err)

	b, err := hashDatapath(fakeConfigWriter("b"), &dummyNodeCfg, nil)
	require.NoError(t, err)
	require.NotEqual(t, a, b)

	// Ensure we get the same base hash when config is the same.
	b, err = hashDatapath(fakeConfigWriter("a"), &dummyNodeCfg, nil)
	require.NoError(t, err)
	require.Equal(t, a, b)

	// A different producer must not share the hash.
	c, err := hashDatapath(fakeConfigWriter("a"), &dummyNodeCfg, []byte("producer"))
	require.NoError(t, err)
	require.NotEqual(t, a, c)
}

func TestHashProducer(t *testing.T) {
	setupCompilationDirectories(t)
	logger := hivetest.Logger(t)
	ctx := t.Context()

	dir := t.TempDir()
	source := filepath.Join(dir, "include", endpointProg)
	require.NoError(t, os.MkdirAll(filepath.Dir(source), 0755))
	require.NoError(t, os.WriteFile(source, []byte("one"), 0644))

	a, err := hashProducer(ctx, logger, dir)
	require.NoError(t, err)
	b, err := hashProducer(ctx, logger, dir)
	require.NoError(t, err)
	require.Equal(t, a, b)

	require.NoError(t, os.WriteFile(source, []byte("two"), 0644))
	c, err := hashProducer(ctx, logger, dir)
	require.NoError(t, err)
	require.NotEqual(t, a, c)

	_, err = hashProducer(ctx, logger, filepath.Join(dir, "absent"))
	require.Error(t, err)
}

func TestHashEndpoint(t *testing.T) {
	var base datapathHash
	ep := testutils.NewTestEndpoint(t)
	cfg := configWriterForTest(t)

	// Error from ConfigWriter is forwarded.
	_, err := base.hashEndpoint(fakeConfigWriter{}, nil, nil)
	require.Error(t, err)

	// Hashing the endpoint gives a hash distinct from the base.
	a, err := base.hashEndpoint(cfg, &localNodeConfig, &ep)
	require.NoError(t, err)
	require.NotEqual(t, base.String(), a)

	// When we configure the endpoint differently, it's different
	ep.Opts.SetBool("foo", true)
	b, err := base.hashEndpoint(cfg, &localNodeConfig, &ep)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestHashTemplate(t *testing.T) {
	var base datapathHash
	ep := testutils.NewTestEndpoint(t)
	cfg := configWriterForTest(t)

	// Error from ConfigWriter is forwarded.
	_, err := base.hashTemplate(fakeConfigWriter{}, nil)
	require.Error(t, err)

	// Hashing the endpoint gives a hash distinct from the base.
	a, err := base.hashTemplate(cfg, &ep)
	require.NoError(t, err)
	require.NotEqual(t, base.String(), a)

	// Even with different endpoint IDs, we get the same hash
	//
	// This is the key to avoiding recompilation per endpoint; static
	// data substitution is performed via pkg/elf instead.
	ep.Id++
	b, err := base.hashTemplate(cfg, &ep)
	require.NoError(t, err)
	require.Equal(t, a, b)

	// The host endpoint must not share the workload endpoint template cache
	// entry, even with the exact same configuration.
	hostEP := testutils.NewTestHostEndpoint(t)
	hostHash, err := base.hashTemplate(cfg, &hostEP)
	require.NoError(t, err)
	require.NotEqual(t, a, hostHash)
}

type fakeConfigWriter []byte

func (fc fakeConfigWriter) WriteNodeConfig(w io.Writer, lnc *config.Config) error {
	if lnc == nil {
		return errors.New("LocalNodeConfiguration is nil")
	}
	_, err := w.Write(fc)
	return err
}

func (fc fakeConfigWriter) WriteNetdevConfig(w io.Writer, opts *option.IntOptions) error {
	return errors.New("not implemented")
}

func (fc fakeConfigWriter) WriteTemplateConfig(w io.Writer, cfg endpoint.Config) error {
	return errors.New("not implemented")
}

func (fc fakeConfigWriter) WriteEndpointConfig(w io.Writer, cfg endpoint.Config) error {
	return errors.New("not implemented")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	dummyNodeCfg = datapath.LocalNodeConfiguration{}
)

// TestHashDatapath is done in this package just for easy access to dummy
// configuration objects.
func TestHashDatapath(t *testing.T) {
	// Error from ConfigWriter is forwarded.
	_, err := hashDatapath(fakeConfigWriter{}, nil)
	require.Error(t, err)

	// Ensure we get different hashes when config is changed
	a, err := hashDatapath(fakeConfigWriter("a"), &dummyNodeCfg)
	require.NoError(t, err)

	b, err := hashDatapath(fakeConfigWriter("b"), &dummyNodeCfg)
	require.NoError(t, err)
	require.NotEqual(t, a, b)

	// Ensure we get the same base hash when config is the same.
	b, err = hashDatapath(fakeConfigWriter("a"), &dummyNodeCfg)
	require.NoError(t, err)
	require.Equal(t, a, b)
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
	_, err := base.hashTemplate(fakeConfigWriter{}, nil, nil)
	require.Error(t, err)

	// Hashing the endpoint gives a hash distinct from the base.
	a, err := base.hashTemplate(cfg, &localNodeConfig, &ep)
	require.NoError(t, err)
	require.NotEqual(t, base.String(), a)

	// Even with different endpoint IDs, we get the same hash
	//
	// This is the key to avoiding recompilation per endpoint; static
	// data substitution is performed via pkg/elf instead.
	ep.Id++
	b, err := base.hashTemplate(cfg, &localNodeConfig, &ep)
	require.NoError(t, err)
	require.Equal(t, a, b)
}

type fakeConfigWriter []byte

func (fc fakeConfigWriter) WriteNodeConfig(w io.Writer, lnc *datapath.LocalNodeConfiguration) error {
	if lnc == nil {
		return errors.New("LocalNodeConfiguration is nil")
	}
	_, err := w.Write(fc)
	return err
}

func (fc fakeConfigWriter) WriteNetdevConfig(w io.Writer, opts *option.IntOptions) error {
	return errors.New("not implemented")
}

func (fc fakeConfigWriter) WriteTemplateConfig(w io.Writer, _ *datapath.LocalNodeConfiguration, cfg datapath.EndpointConfiguration) error {
	return errors.New("not implemented")
}

func (fc fakeConfigWriter) WriteEndpointConfig(w io.Writer, _ *datapath.LocalNodeConfiguration, cfg datapath.EndpointConfiguration) error {
	return errors.New("not implemented")
}

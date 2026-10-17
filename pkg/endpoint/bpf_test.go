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

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

type fakeDNSRulesAPI struct{}

func (*fakeDNSRulesAPI) GetDNSRules(uint16) restore.DNSRules { return nil }

func (*fakeDNSRulesAPI) RemoveRestoredDNSRules(uint16) {}

func TestRegenerateBPFFailureReverts(t *testing.T) {
	logger := hivetest.Logger(t)
	repo := policy.NewPolicyRepository(logger, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	// Fake endpoints skip the proxy state finalization that this test exercises.
	delete(model.Properties, PropertyFakeEndpoint)

	e, err := NewEndpointFromChangeModel(t.Context(), logger, &fakeDNSRulesAPI{}, &MockEndpointBuildQueue{}, nil, &fakeTypes.FakeOrchestrator{}, &lock.RWMutex{}, nil, nil, identitymanager.NewIDManager(logger), nil, nil, repo, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil)
	require.NoError(t, err)

	e.logger.Store(logger)
	datapath := &datapathRegenerationContext{
		ctCleaned: make(chan struct{}),
	}
	var reverted bool
	datapath.revertStack.Push(func() error {
		reverted = true
		return nil
	})

	e.buildMutex.Lock()
	defer e.buildMutex.Unlock()
	_, err = e.regenerateBPF(&regenerationContext{
		parentContext:               t.Context(),
		datapathRegenerationContext: datapath,
	})
	<-datapath.ctCleaned
	require.ErrorContains(t, err, "endpoint has nil policyMapFactory")
	require.True(t, reverted)
}

func TestWriteInformationalComments(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointSuite(t)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	e, err := NewEndpointFromChangeModel(t.Context(), logger, nil, &MockEndpointBuildQueue{}, nil, s.orchestrator, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil)
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
	e, err := NewEndpointFromChangeModel(b.Context(), logger, nil, &MockEndpointBuildQueue{}, nil, s.orchestrator, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model, fakeTypes.WireguardConfig{}, &fakeTypes.IPsecConfig{}, nil, nil)
	require.NoError(b, err)

	e.Start(uint16(model.ID))
	b.Cleanup(e.Stop)

	configWriter := &config.HeaderfileWriter{}
	cfg := datapath.LocalNodeConfiguration{}

	targetComments := func(w io.Writer) error {
		return e.writeInformationalComments(w)
	}
	targetConfig := func(w io.Writer) error {
		return configWriter.WriteEndpointConfig(w, &cfg, e)
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
			for b.Loop() {
				if err := bm.write(bm.output); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

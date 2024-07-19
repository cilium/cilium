// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	nodemapFake "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	dummyNodeCfg = datapath.LocalNodeConfiguration{
		MtuConfig: &fake.MTU{},
	}
	dummyDevCfg = testutils.NewTestEndpoint()
	dummyEPCfg  = testutils.NewTestEndpoint()
)

// TesthashDatapath is done in this package just for easy access to dummy
// configuration objects.
func (s *LoaderTestSuite) TesthashDatapath(c *C) {
	var cfg datapath.ConfigWriter
	hv := hive.New(
		provideNodemap,
		cell.Provide(
			fake.NewNodeAddressing,
			func() datapath.BandwidthManager { return &fake.BandwidthManager{} },
			config.NewHeaderfileWriter,
		),
		cell.Invoke(func(writer_ datapath.ConfigWriter) {
			cfg = writer_
		}),
	)

	require.NoError(c, hv.Start(context.TODO()))
	c.Cleanup(func() { require.Nil(c, hv.Stop(context.TODO())) })

	h := newDatapathHash()
	baseHash := h.String()

	// Ensure we get different hashes when config is added
	h = hashDatapath(cfg, &dummyNodeCfg, &dummyDevCfg, &dummyEPCfg)
	dummyHash := h.String()
	c.Assert(dummyHash, Not(Equals), baseHash)

	// Ensure we get the same base hash when config is removed via Reset()
	h.Reset()
	c.Assert(h.String(), Equals, baseHash)
	c.Assert(h.String(), Not(Equals), dummyHash)

	// Ensure that with a copy of the endpoint config we get the same hash
	newEPCfg := dummyEPCfg
	h = hashDatapath(cfg, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Equals, dummyHash)

	// Even with different endpoint IDs, we get the same hash
	//
	// This is the key to avoiding recompilation per endpoint; static
	// data substitution is performed via pkg/elf instead.
	newEPCfg.Id++
	h = hashDatapath(cfg, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Equals, dummyHash)

	// But when we configure the endpoint differently, it's different
	newEPCfg = testutils.NewTestEndpoint()
	newEPCfg.Opts.SetBool("foo", true)
	h = hashDatapath(cfg, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Not(Equals), dummyHash)
}

var provideNodemap = cell.Provide(func() nodemap.Map {
	return nodemapFake.NewFakeNodeMap()
})

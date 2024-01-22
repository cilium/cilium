// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"context"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/testutils"
)

func (s *LoaderTestSuite) TestWrap(c *C) {
	var (
		realEPBuffer   bytes.Buffer
		templateBuffer bytes.Buffer
		cfg            types.ConfigWriter
	)

	h := hive.New(
		statedb.Cell,
		tables.DirectRoutingDeviceCell,
		cell.Provide(
			fake.NewNodeAddressing,
			func() sysctl.Sysctl { return sysctl.NewTestSysctl(c) },
			tables.NewDeviceTable,
			func(_ *statedb.DB, devices statedb.RWTable[*tables.Device]) statedb.Table[*tables.Device] {
				return devices
			},
			config.NewHeaderfileWriter,
		),
		cell.Invoke(statedb.RegisterTable[*tables.Device]),
		cell.Invoke(func(writer_ datapath.ConfigWriter) {
			cfg = writer_
		}),
	)
	require.NoError(c, h.Start(context.TODO()))
	c.Cleanup(func() { require.Nil(c, h.Stop(context.TODO())) })

	realEP := testutils.NewTestEndpoint()
	template := wrap(&realEP, nil)

	// Write the configuration that should be the same, and verify it is.
	err := cfg.WriteTemplateConfig(&realEPBuffer, &realEP)
	c.Assert(err, IsNil)
	err = cfg.WriteTemplateConfig(&templateBuffer, template)
	c.Assert(err, IsNil)
	c.Assert(realEPBuffer.String(), checker.DeepEquals, templateBuffer.String())

	// Write with the static data, and verify that the buffers differ.
	// Note this isn't an overly strong test because it only takes one
	// character to change for this test to pass, but we would ideally
	// define every bit of static data differently in the templates.
	realEPBuffer.Reset()
	templateBuffer.Reset()
	err = cfg.WriteEndpointConfig(&realEPBuffer, &realEP)
	c.Assert(err, IsNil)
	err = cfg.WriteEndpointConfig(&templateBuffer, template)
	c.Assert(err, IsNil)
	c.Assert(realEPBuffer.String(), Not(Equals), templateBuffer.String())
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/testutils"
)

func (s *LoaderTestSuite) TestWrap(c *C) {
	var (
		realEPBuffer   bytes.Buffer
		templateBuffer bytes.Buffer
	)

	realEP := testutils.NewTestEndpoint()
	template := wrap(&realEP, nil)
	devices := statedb.MustNewTable[*tables.Device]("devices", tables.DeviceIDIndex, tables.DeviceNameIndex, tables.DeviceSelectedIndex)
	db, err := statedb.NewDB([]statedb.TableMeta{devices}, statedb.NewMetrics())
	if err != nil {
		c.Fatalf("failed to create statedb: %v", err)
	}
	cfg, err := config.NewHeaderfileWriter(config.WriterParams{
		DB:      db,
		Devices: devices,
		Sysctl:  sysctl.NewTestSysctl(c),
	})
	if err != nil {
		c.Fatalf("failed to create header file writer: %v", err)
	}

	// Write the configuration that should be the same, and verify it is.
	err = cfg.WriteTemplateConfig(&realEPBuffer, &realEP)
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

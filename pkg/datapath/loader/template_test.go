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

package loader

import (
	"bytes"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

func (s *LoaderTestSuite) TestWrap(c *C) {
	var (
		realEPBuffer   bytes.Buffer
		templateBuffer bytes.Buffer
	)

	realEP := testutils.NewTestEndpoint()
	template := wrap(&realEP, nil)
	cfg := &config.HeaderfileWriter{}

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

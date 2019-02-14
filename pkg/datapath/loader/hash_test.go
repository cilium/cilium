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
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

var (
	dummyNodeCfg = datapath.LocalNodeConfiguration{}
	dummyDevCfg  = testutils.NewTestEndpoint()
	dummyEPCfg   = testutils.NewTestEndpoint()
)

// TestHashDatapath is done in this package just for easy access to dummy
// configuration objects.
func (s *LoaderTestSuite) TestHashDatapath(c *C) {
	dp := linux.NewDatapath(linux.DatapathConfiguration{})
	h := NewHash(dp)
	baseHash := h.String()

	// Ensure we get different hashes when config is added
	h = HashDatapath(dp, &dummyNodeCfg, &dummyDevCfg, &dummyEPCfg)
	dummyHash := h.String()
	c.Assert(dummyHash, Not(Equals), baseHash)

	// Ensure we get the same base hash when config is removed via Reset()
	h.Reset()
	c.Assert(h.String(), Equals, baseHash)
	c.Assert(h.String(), Not(Equals), dummyHash)

	// Ensure that with a copy of the endpoint config we get the same hash
	newEPCfg := dummyEPCfg
	h = HashDatapath(dp, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Equals, dummyHash)

	// Even with different endpoint IDs, we get the same hash
	//
	// This is the key to avoiding recompilation per endpoint; static
	// data substitution is performed via pkg/elf instead.
	newEPCfg.Id++
	h = HashDatapath(dp, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Equals, dummyHash)

	// But when we configure the endpoint differently, it's different
	newEPCfg = testutils.NewTestEndpoint()
	newEPCfg.Opts.SetBool("foo", true)
	h = HashDatapath(dp, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Not(Equals), dummyHash)
}

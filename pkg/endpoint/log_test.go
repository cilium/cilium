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

package endpoint

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils/allocator"

	. "gopkg.in/check.v1"
)

func (s *EndpointSuite) TestPolicyLog(c *C) {
	ep := NewEndpointWithState(&DummyOwner{repo: policy.NewPolicyRepository(nil, nil)}, nil, &allocator.FakeIdentityAllocator{}, 12345, StateReady)

	// Initially nil
	policyLogger := ep.getPolicyLogger()
	c.Assert(policyLogger, IsNil)

	// Enable DebugPolicy option
	ep.Options.SetValidated(option.DebugPolicy, option.OptionEnabled)
	c.Assert(ep.Options.IsEnabled(option.DebugPolicy), Equals, true)
	ep.UpdateLogger(nil)
	policyLogger = ep.getPolicyLogger()
	c.Assert(policyLogger, Not(IsNil))

	// Test logging
	policyLogger.Info("testing policy logging")

	// Disable option
	ep.Options.SetValidated(option.DebugPolicy, option.OptionDisabled)
	c.Assert(ep.Options.IsEnabled(option.DebugPolicy), Equals, false)
	ep.UpdateLogger(nil)
	policyLogger = ep.getPolicyLogger()
	c.Assert(policyLogger, IsNil)

	// Verify file exists and contains the logged message
	buf, err := ioutil.ReadFile(filepath.Join(ep.StateDirectoryPath(), "policy.log"))
	c.Assert(err, IsNil)
	c.Assert(bytes.Contains(buf, []byte("testing policy logging")), Equals, true)

	// remote created files/directory
	err = os.RemoveAll(ep.StateDirectoryPath())
	c.Assert(err, IsNil)
}

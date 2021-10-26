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
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

func (s *EndpointSuite) TestPolicyLog(c *C) {
	ep := NewEndpointWithState(&DummyOwner{repo: policy.NewPolicyRepository(nil, nil, nil)}, nil, testidentity.NewFakeIdentityAllocator(nil), 12345, StateReady)

	// Initially nil
	policyLogger := ep.getPolicyLogger()
	c.Assert(policyLogger, IsNil)

	// Enable DebugPolicy option
	ep.Options.SetValidated(option.DebugPolicy, option.OptionEnabled)
	c.Assert(ep.Options.IsEnabled(option.DebugPolicy), Equals, true)
	ep.UpdateLogger(nil)
	policyLogger = ep.getPolicyLogger()
	c.Assert(policyLogger, Not(IsNil))
	defer func() {
		// remote created log file when we are done.
		err := os.Remove(filepath.Join(option.Config.StateDir, "endpoint-policy.log"))
		c.Assert(err, IsNil)
	}()

	// Test logging, policyLogger must not be nil
	policyLogger.Info("testing policy logging")

	// Test logging with integrated nil check, no fields
	ep.policyDebug(nil, "testing policyDebug")
	ep.policyDebug(logrus.Fields{"testField": "Test Value"}, "policyDebug with fields")

	// Disable option
	ep.Options.SetValidated(option.DebugPolicy, option.OptionDisabled)
	c.Assert(ep.Options.IsEnabled(option.DebugPolicy), Equals, false)
	ep.UpdateLogger(nil)
	policyLogger = ep.getPolicyLogger()
	c.Assert(policyLogger, IsNil)

	// Verify file exists and contains the logged message
	buf, err := os.ReadFile(filepath.Join(option.Config.StateDir, "endpoint-policy.log"))
	c.Assert(err, IsNil)
	c.Assert(bytes.Contains(buf, []byte("testing policy logging")), Equals, true)
	c.Assert(bytes.Contains(buf, []byte("testing policyDebug")), Equals, true)
	c.Assert(bytes.Contains(buf, []byte("Test Value")), Equals, true)
}

//
// Copyright 2016 Authors of Cilium
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
//
package server

import (
	"errors"
	"strings"

	"github.com/cilium/cilium/common/types"

	. "gopkg.in/check.v1"
)

func (s *DaemonSuite) TestGlobalStatusOK(c *C) {
	sr := &types.StatusResponse{Cilium: types.NewStatusOK("Foo")}
	s.d.OnGlobalStatus = func() (*types.StatusResponse, error) {
		return &sr, nil
	}

	resp, err := s.c.GlobalStatus()
	c.Assert(resp, DeepEquals, sr)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestGlobalStatusFail(c *C) {
	var nilResponse *types.StatusResponse
	s.d.OnGlobalStatus = func() (*types.StatusResponse, error) {
		return nil, errors.New("I'll fail")
	}

	res, err := s.c.GlobalStatus()
	c.Assert(res, Equals, nilResponse)
	c.Assert(strings.Contains(err.Error(), "I'll fail"), Equals, true)
}

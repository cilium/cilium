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

package policy

import (
	"github.com/cilium/cilium/pkg/u8proto"
	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestVisibilityPolicyCreation(c *C) {

	anno := "<Ingress/80/TCP/HTTP>"
	vp, err := NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.Ingress), Equals, 1)
	c.Assert(vp.Ingress["80/TCP"], DeepEquals, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	})

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/8080/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.Ingress), Equals, 2)
	c.Assert(vp.Ingress["80/TCP"], DeepEquals, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	})
	c.Assert(vp.Ingress["8080/TCP"], DeepEquals, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(8080),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	})

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/80/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.Ingress), Equals, 1)
	c.Assert(vp.Ingress["80/TCP"], DeepEquals, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	})

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/80/TCP/Kafka>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "asdf"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "<Ingress/65536/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "<Ingress/65535/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	anno = "<Ingress/99999/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "<Ingress/0/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	// Do not allow > 5 digits.
	anno = "<Ingress/123456/TCP/HTTP"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	// Do not allow leading zeroes.
	anno = "<Ingress/02345/TCP/HTTP"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))
}

// Copyright 2018 Authors of Cilium
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

package proxylib

import (
	"github.com/cilium/proxy/go/cilium/api"
	envoy_api_v2 "github.com/cilium/proxy/go/envoy/api/v2"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

func (ins *Instance) CheckInsertPolicyText(c *C, version string, policies []string) {
	err := ins.InsertPolicyText(version, policies, "")
	c.Assert(err, IsNil)
}

func (ins *Instance) InsertPolicyText(version string, policies []string, expectFail string) error {
	typeUrl := "type.googleapis.com/cilium.NetworkPolicy"
	resources := make([]*any.Any, 0, len(policies))

	for _, policy := range policies {
		pb := new(cilium.NetworkPolicy)
		err := proto.UnmarshalText(policy, pb)
		if err != nil {
			if expectFail != "unmarshal" {
				log.Fatalf("Policy UnmarshalText failed: %v", err)
			}
			return err
		}
		log.Debugf("Text -> proto.Message: %s -> %v", policy, pb)
		data, err := proto.Marshal(pb)
		if err != nil {
			if expectFail != "marshal" {
				log.Fatalf("Policy marshal failed: %v", err)
			}
			return err
		}

		resources = append(resources, &any.Any{
			TypeUrl: typeUrl,
			Value:   data,
		})
	}

	msg := &envoy_api_v2.DiscoveryResponse{
		VersionInfo: version,
		Canary:      false,
		TypeUrl:     typeUrl,
		Nonce:       "randomNonce1",
		Resources:   resources,
	}

	err := ins.PolicyUpdate(msg)
	if err != nil {
		if expectFail != "update" {
			log.Fatalf("Policy Update failed: %v", err)
		}
	}
	return err
}

var connectionID uint64

func (ins *Instance) CheckNewConnectionOK(c *C, proto string, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string) *Connection {
	err, conn := ins.CheckNewConnection(c, proto, ingress, srcId, dstId, srcAddr, dstAddr, policyName)
	c.Assert(err, IsNil)
	c.Assert(conn, Not(IsNil))
	return conn
}

func (ins *Instance) CheckNewConnection(c *C, proto string, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string) (error, *Connection) {
	connectionID++
	bufSize := 1024
	origBuf := make([]byte, 0, bufSize)
	replyBuf := make([]byte, 0, bufSize)

	return NewConnection(ins, proto, connectionID, ingress, srcId, dstId, srcAddr, dstAddr, policyName, &origBuf, &replyBuf)
}

func (conn *Connection) CheckOnDataOK(c *C, reply, endStream bool, data *[][]byte, expReplyBuf []byte, expOps ...interface{}) {
	conn.CheckOnData(c, reply, endStream, data, OK, expReplyBuf, expOps...)
}

func (conn *Connection) CheckOnData(c *C, reply, endStream bool, data *[][]byte, expResult FilterResult, expReplyBuf []byte, expOps ...interface{}) {
	ops := make([][2]int64, 0, len(expOps)/2)

	res := conn.OnData(reply, endStream, data, &ops)
	c.Check(res, Equals, expResult)

	c.Check(len(ops), Equals, len(expOps)/2, Commentf("Unexpected number of filter operations"))
	for i, op := range ops {
		if i*2+1 < len(expOps) {
			expOp, ok := expOps[i*2].(OpType)
			c.Assert(ok, Equals, true, Commentf("Invalid expected operation type"))
			c.Check(op[0], Equals, int64(expOp), Commentf("Unexpected filter operation"))
			expN, ok := expOps[i*2+1].(int)
			c.Assert(ok, Equals, true, Commentf("Invalid expected operation length (must be int)"))
			c.Check(op[1], Equals, int64(expN), Commentf("Unexpected operation length"))
		}
	}

	buf := conn.ReplyBuf
	c.Check(*buf, DeepEquals, expReplyBuf, Commentf("Inject buffer mismatch"))
	*buf = (*buf)[:0] // make empty again

	// Clear the same-direction inject buffer, simulating the datapath forwarding the injected data
	injectBuf := conn.getInjectBuf(reply)
	*injectBuf = (*injectBuf)[:0]
	log.Debugf("proxylib test helper: Cleared inject buf, used %d/%d", len(*injectBuf), cap(*injectBuf))
}

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

package main

import (
	//	"path/filepath"
	"testing"
	"time"

	_ "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
	_ "github.com/cilium/cilium/proxylib/testparsers"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	log "github.com/sirupsen/logrus"
)

func TestInitModule(t *testing.T) {
	if !InitModule([][2]string{}, true) {
		t.Error("InitModule() with empty params failed")
	}

	if InitModule([][2]string{{"dummy-key", "dummy-value"}, {"key2", "value2"}}, true) {
		t.Error("InitModule() with unknown params accepted")
	}

	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}
}

func TestOnNewConnection(t *testing.T) {
	if !InitModule([][2]string{}, true) {
		t.Error("InitModule() with empty access log name failed")
	}

	// Unkhown parser
	CheckOnNewConnection(t, "invalid-parser-should-not-exist", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "policy-1", 80, proxylib.UNKNOWN_PARSER, 0)

	// Non-numeric destination port
	CheckOnNewConnection(t, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:XYZ", "policy-1",
		80, proxylib.INVALID_ADDRESS, 0)

	// Missing Destination port
	CheckOnNewConnection(t, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2", "policy-1",
		80, proxylib.INVALID_ADDRESS, 0)

	// Zero Destination port is reserved for wildcarding
	CheckOnNewConnection(t, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:0", "policy-1",
		80, proxylib.INVALID_ADDRESS, 0)

	// L7 parser rejecting the connection based on connection metadata
	CheckOnNewConnection(t, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "invalid-policy",
		80, proxylib.POLICY_DROP, 0)

	// Using test parser
	CheckOnNewConnection(t, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "policy-1",
		80, proxylib.OK, 1)

	// 2nd connection
	CheckOnNewConnection(t, "test.passer", 12345678901234567890, false, 2, 1, "2.2.2.2:80", "1.1.1.1:34567", "policy-2",
		80, proxylib.OK, 2)

	CheckClose(t, 1, nil, 2)

	CheckClose(t, 12345678901234567890, nil, 1)
}

func checkAccessLogs(t *testing.T, logServer *test.AccessLogServer, expPasses, expDrops int) {
	t.Helper()
	passes, drops := 0, 0
	empty := false
	for !empty {
		select {
		case pblog := <-logServer.Logs:
			if pblog.EntryType == cilium.EntryType_Denied {
				drops++
			} else {
				passes++
			}
		case <-time.After(10 * time.Millisecond):
			empty = true
		}
	}

	if !(passes == expPasses && drops == expDrops) {
		t.Errorf("OnData: Unexpected access log entries, expected %d passes (got %d) and %d drops (got %d).", expPasses, passes, expDrops, drops)
	}
}

func TestOnDataNoPolicy(t *testing.T) {
	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	// Using headertester parser
	buf := CheckOnNewConnection(t, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "policy-1",
		30, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3 := "No policy\n", "Dropped\n", "foo"
	data := line1 + line2 + line3
	CheckOnData(t, 1, false, false, &[]string{data}, []ExpFilterOp{
		{proxylib.DROP, len(line1)},
		{proxylib.DROP, len(line2)},
		{proxylib.MORE, 1},
	}, proxylib.OK, "Line dropped: "+line1+"Line dropped: "+line2)

	// No new input
	CheckOnData(t, 1, false, false, &[]string{line3}, []ExpFilterOp{
		{proxylib.MORE, 1},
	}, proxylib.OK, "")

	// Empty
	CheckOnData(t, 1, false, false, &[]string{""}, []ExpFilterOp{}, proxylib.OK, "")

	expPasses, expDrops := 0, 2
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

func insertPolicyText(t *testing.T, version string, policies []string) bool {
	return insertPolicyTextRaw(t, version, policies, "") == nil
}

func insertPolicyTextRaw(t *testing.T, version string, policies []string, expectFail string) error {
	typeUrl := "type.googleapis.com/cilium.NetworkPolicy"
	var resources []*any.Any

	for _, policy := range policies {
		pb := new(cilium.NetworkPolicy)
		err := proto.UnmarshalText(policy, pb)
		if err != nil {
			if expectFail != "unmarshal" {
				t.Errorf("Policy UnmarshalText failed: %v", err)
			}
			return err
		}
		log.Infof("Text -> proto.Message: %s -> %v", policy, pb)
		data, err := proto.Marshal(pb)
		if err != nil {
			if expectFail != "marshal" {
				t.Errorf("Policy marshal failed: %v", err)
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
	err := proxylib.PolicyUpdate(msg)
	if err != nil {
		if expectFail != "update" {
			t.Errorf("Policy Update failed: %v", err)
		}
		return err
	}
	return nil
}

func TestUnsupportedL7Drops(t *testing.T) {
	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "FooBar"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    kafka_rules: <
		      kafka_rules: <
			topic: "Topic"
		      >
		    >
		  >
		>
		`})

	// Using headertester parser
	buf := CheckOnNewConnection(t, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "FooBar",
		256, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "Beginning----\n", "foo\n", "----End\n", "\n"
	data := line1 + line2 + line3 + line4
	CheckOnData(t, 1, false, false, &[]string{data}, []ExpFilterOp{
		{proxylib.DROP, len(line1)},
		{proxylib.DROP, len(line2)},
		{proxylib.DROP, len(line3)},
		{proxylib.DROP, len(line4)},
	}, proxylib.OK, "Line dropped: "+line1+"Line dropped: "+line2+"Line dropped: "+line3+"Line dropped: "+line4)

	expPasses, expDrops := 0, 4
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

func TestTwoRulesOnSamePortFirstNoL7(t *testing.T) {
	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "FooBar"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 11
		  >
		  rules: <
		    remote_policies: 11
		    http_rules: <
		      http_rules: <
			headers: <
			  name: ":path"
			  exact_match: "/allowed"
			>
		      >
		    >
		  >
		>
		`})
}

func TestSimplePolicy(t *testing.T) {
	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "FooBar"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    http_rules: <
		      http_rules: <
		        headers: <
		          name: "from"
		          exact_match: "someone"
		        >
		      >
		      http_rules: <
		        headers: <
		          name: "to"
		          exact_match: "else"
		        >
		      >
		    >
		  >
		>
		`})

	// Using headertester parser
	buf := CheckOnNewConnection(t, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "FooBar",
		80, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "from=someone\n", "foo\n", "to=else\n", "\n"
	data := line1 + line2 + line3 + line4
	CheckOnData(t, 1, false, false, &[]string{data}, []ExpFilterOp{
		{proxylib.PASS, len(line1)},
		{proxylib.DROP, len(line2)},
		{proxylib.PASS, len(line3)},
		{proxylib.DROP, len(line4)},
	}, proxylib.OK, "Line dropped: "+line2+"Line dropped: "+line4)

	expPasses, expDrops := 2, 2
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

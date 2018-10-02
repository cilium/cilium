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
	"testing"

	_ "gopkg.in/check.v1"

	binarymemcached "github.com/cilium/cilium/proxylib/memcached/binary"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
	_ "github.com/cilium/cilium/proxylib/testparsers"
)

var getHello = []byte{
	128, 0, 0, 5,
	0, 0, 0, 0,
	0, 0, 0, 5,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	'H', 'e', 'l', 'l',
	'o',
}

var getHelloResp = []byte{
	129, 0, 0, 0,
	4, 0, 0, 0,
	0, 0, 0, 9,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	'W', 'o', 'r', 'l',
	'd',
}

var setHello = []byte{
	128, 1, 0, 5,
	8, 0, 0, 0,
	0, 0, 0, 18,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	'H', 'e', 'l', 'l',
	'o', 'W', 'o', 'r',
	'l', 'd',
}

func TestBinaryMemcacheOnDataReq(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "opCode"
				  value: "get"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1",
		30, proxylib.OK, 1)

	CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
		{proxylib.PASS, len(getHello)}, {proxylib.MORE, 24},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestBinaryMemcacheOnDataReqKey(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyExact"
		          value: "Hello"
				>
				rule: <
				  key: "opCode"
				  value: "get"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1",
		30, proxylib.OK, 1)

	CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
		{proxylib.PASS, len(getHello)}, {proxylib.MORE, 24},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestBinaryMemcacheOnDataReqKeyPrefix(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyPrefix"
		          value: "Hell"
				>
				rule: <
				  key: "opCode"
				  value: "get"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1",
		30, proxylib.OK, 1)

	CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
		{proxylib.PASS, len(getHello)}, {proxylib.MORE, 24},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestBinaryMemcacheOnDataReqKeyRegex(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyRegex"
		          value: "^.el.o$"
				>
				rule: <
				  key: "opCode"
				  value: "readGroup"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1",
		30, proxylib.OK, 1)

	CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
		{proxylib.PASS, len(getHello)}, {proxylib.MORE, 24},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestBinaryMemcacheOnDataReqDrop(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "opCode"
				  value: "set"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1", 30, proxylib.OK, 1)

	CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
		{proxylib.DROP, len(getHello)}, {proxylib.MORE, 24},
	}, proxylib.OK, string(binarymemcached.DeniedMsgBase))

	CheckClose(t, 1, buf, 1)
}

func TestBinaryMemcacheOnDataReqMore(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "opCode"
				  value: "readGroup"
		        >
		      >
		    >
		  >
		>
		`})

	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1", 30, proxylib.OK, 1)

	data := getHello[:10]
	CheckOnData(t, 1, false, false, &[][]byte{data}, []ExpFilterOp{{proxylib.MORE, 14}}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestBinaryMemcacheOnDataReqSplit(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "opCode"
				  value: "readGroup"
		        >
		      >
		    >
		  >
		>
		`})

	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1", 30, proxylib.OK, 1)

	data := getHello
	CheckOnData(t, 1, false, false, &[][]byte{data[:10], data[10:]}, []ExpFilterOp{
		{proxylib.PASS, len(data)}, {proxylib.MORE, 24},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestBinaryMemcacheOnDataReqGetRemainingKey(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "opCode"
				  value: "readGroup"
		        >
		      >
		    >
		  >
		>
		`})

	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1", 30, proxylib.OK, 1)

	data := getHello[:26]
	CheckOnData(t, 1, false, false, &[][]byte{data}, []ExpFilterOp{
		{proxylib.MORE, 3},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestBinaryMemcacheOnDataReqDropAndAllow(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "binarymemcache"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "opCode"
				  value: "set"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, mod, "binarymemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1", 120, proxylib.OK, 1)

	CheckOnData(t, 1, false, false, &[][]byte{setHello, getHello}, []ExpFilterOp{
		{proxylib.PASS, len(setHello)}, {proxylib.DROP, len(getHello)}, {proxylib.MORE, 24},
	}, proxylib.OK, string(binarymemcached.DeniedMsgBase))

	CheckOnData(t, 1, true, false, &[][]byte{getHelloResp}, []ExpFilterOp{
		{proxylib.PASS, len(getHelloResp)}, {proxylib.INJECT, len(binarymemcached.DeniedMsgBase)},
	}, proxylib.OK, string(binarymemcached.DeniedMsgBase))

	CheckClose(t, 1, buf, 1)
}

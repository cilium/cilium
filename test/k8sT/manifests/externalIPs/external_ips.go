// Copyright 2020 Authors of Cilium
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

package external_ips

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/extensions/table"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type entryTestArgs struct {
	description string
	expected    string
	ip          string
	port        string
	skipReason  string
}

func run(ns, pod, ip, port string) string {
	cmd := exec.Command("kubectl",
		"exec",
		"-n",
		ns,
		pod,
		"-c",
		"curl",
		"--",
		"curl",
		"--connect-timeout",
		"2",
		"-v",
		net.JoinHostPort(ip, port),
	)
	b, _ := cmd.CombinedOutput()
	str := string(b)
	var got string
	switch {
	case strings.Contains(str, "Guestbook"):
		got = "app1"
	case strings.Contains(str, "Connection refused"):
		got = "connection refused"
	case strings.Contains(str, "No route to host"),
		strings.Contains(str, "Host is unreachable"),
		strings.Contains(str, "Connection timed out"):
		got = "No route to host / connection timed out"
	case strings.Contains(str, "It works!"):
		got = "app2"
	case strings.Contains(str, "app4"):
		got = "app4"
	case strings.Contains(str, "app6"):
		got = "app6"
	default:
		got = "None? " + str
	}
	return got
}

func getTableEntries(expectedResult map[string]map[string]entryTestArgs) []TableEntry {
	var te []TableEntry
	for _, ipPortTest := range expectedResult {
		for _, testCaseExpected := range ipPortTest {
			te = append(te, Entry(
				fmt.Sprintf("%s curl %s",
					testCaseExpected.description,
					net.JoinHostPort(testCaseExpected.ip, testCaseExpected.port),
				),
				testCaseExpected.ip,
				testCaseExpected.port,
				testCaseExpected.expected,
				testCaseExpected.skipReason,
			))
		}
	}
	return te
}

var _ = Describe("Kube-proxy service tests", func() {
	DescribeTable("From pod running on node-1 to services being backed by a pod running on node-1",
		func(ip, port, expected, skipReason string) {
			namespace := "external-ips-test"
			clientPod := "app1-749d589d77-4qnlh"
			got := run(namespace, clientPod, ip, port)
			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
				}
				Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected))
		},
		getTableEntries(expectedResultFromPodInNode1)...,
	)
	DescribeTable("From host running on node-1 to services being backed by a pod running on node-1",
		func(ip, port, expected, skipReason string) {
			namespace := "external-ips-test"
			clientPod := "host-client-mt4wv"
			got := run(namespace, clientPod, ip, port)
			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
				}
				Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected))
		},
		getTableEntries(expectedResultFromNode1)...,
	)
	DescribeTable("From pod running on node-2 to services being backed by a pod running on node-1",
		func(ip, port, expected, skipReason string) {
			namespace := "external-ips-test"
			clientPod := "app3-cf6c8d494-nvk9v"
			got := run(namespace, clientPod, ip, port)
			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
				}
				Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected))
		},
		getTableEntries(expectedResultFromPodInNode2)...,
	)
	DescribeTable("From host running on node-2 to services being backed by a pod running on node-1",
		func(ip, port, expected, skipReason string) {
			namespace := "external-ips-test"
			clientPod := "host-client-nz96t"
			got := run(namespace, clientPod, ip, port)
			if skipReason != "" {
				if got != expected {
					Skip(skipReason)
				}
				Expect(got).ToNot(Equal(expected), "It seems this test is disabled but your changes have fix this test case")
				return
			}
			Expect(got).To(Equal(expected))
		},
		getTableEntries(expectedResultFromNode2)...,
	)
	// DescribeTable("From host running on node-3 to services being backed by a pod running on node-1",
	// 	func(ip, port, expected , skipReason string) {
	// 		namespace := "external-ips-test"
	// 		clientPod := "host-client-nz96t"
	// 		got := run(namespace, clientPod, ip, port)
	// 		// fmt.Println(cmd, got)
	// 		Expect(got).To(Equal(expected))
	// 	},
	// 	podNode1ToPodNode1...,
	// )
})

func TestBooks(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Books Suite")
}

// Copyright 2016 CNI authors
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
	"io/ioutil"
	"os"

	"github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("parsing resolv.conf", func() {
	It("parses a simple resolv.conf file", func() {
		contents := `
		nameserver 192.0.2.0
		nameserver 192.0.2.1
		`
		dns, err := parse(contents)
		Expect(err).NotTo(HaveOccurred())
		Expect(*dns).Should(Equal(types.DNS{Nameservers: []string{"192.0.2.0", "192.0.2.1"}}))
	})
	It("ignores comments", func() {
		dns, err := parse(`
nameserver 192.0.2.0
;nameserver 192.0.2.1
`)
		Expect(err).NotTo(HaveOccurred())
		Expect(*dns).Should(Equal(types.DNS{Nameservers: []string{"192.0.2.0"}}))
	})
	It("parses all fields", func() {
		dns, err := parse(`
nameserver 192.0.2.0
nameserver 192.0.2.2
domain example.com
;nameserver comment
#nameserver comment
search example.net example.org
search example.gov
options one two three
options four
`)
		Expect(err).NotTo(HaveOccurred())
		Expect(*dns).Should(Equal(types.DNS{
			Nameservers: []string{"192.0.2.0", "192.0.2.2"},
			Domain:      "example.com",
			Search:      []string{"example.net", "example.org", "example.gov"},
			Options:     []string{"one", "two", "three", "four"},
		}))
	})
})

func parse(contents string) (*types.DNS, error) {
	f, err := ioutil.TempFile("", "host_local_resolv")
	defer f.Close()
	defer os.Remove(f.Name())

	if err != nil {
		return nil, err
	}

	if _, err := f.WriteString(contents); err != nil {
		return nil, err
	}

	return parseResolvConf(f.Name())
}

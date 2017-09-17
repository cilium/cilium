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

package utils

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Utils", func() {
	It("must format a short name", func() {
		chain := FormatChainName("test", "1234")
		Expect(len(chain)).To(Equal(maxChainLength))
		Expect(chain).To(Equal("CNI-2bbe0c48b91a7d1b8a6753a8"))
	})

	It("must truncate a long name", func() {
		chain := FormatChainName("testalongnamethatdoesnotmakesense", "1234")
		Expect(len(chain)).To(Equal(maxChainLength))
		Expect(chain).To(Equal("CNI-374f33fe84ab0ed84dcdebe3"))
	})

	It("must be predictable", func() {
		chain1 := FormatChainName("testalongnamethatdoesnotmakesense", "1234")
		chain2 := FormatChainName("testalongnamethatdoesnotmakesense", "1234")
		Expect(len(chain1)).To(Equal(maxChainLength))
		Expect(len(chain2)).To(Equal(maxChainLength))
		Expect(chain1).To(Equal(chain2))
	})

	It("must change when a character changes", func() {
		chain1 := FormatChainName("testalongnamethatdoesnotmakesense", "1234")
		chain2 := FormatChainName("testalongnamethatdoesnotmakesense", "1235")
		Expect(len(chain1)).To(Equal(maxChainLength))
		Expect(len(chain2)).To(Equal(maxChainLength))
		Expect(chain1).To(Equal("CNI-374f33fe84ab0ed84dcdebe3"))
		Expect(chain1).NotTo(Equal(chain2))
	})
})

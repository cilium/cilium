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

package RuntimeTest

import (
	"fmt"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimePrivilegedUnitTests", func() {

	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		res := vm.ExecWithSudo("systemctl stop cilium")
		res.ExpectSuccess("Failed trying to stop cilium via systemctl")
	})

	AfterAll(func() {
		err := vm.RestartCilium()
		Expect(err).Should(BeNil(), "Failed to restart Cilium")
	})

	It("Run Tests", func() {
		res := vm.ExecWithSudo(fmt.Sprintf("make -C %s tests-privileged", helpers.CiliumBasePath))
		res.ExpectSuccess("Failed to run privileged unit tests")
	})
})

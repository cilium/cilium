// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"context"
	"time"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("RuntimeSSHTests", func() {

	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
	})

	It("Should fail when context times out", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		By("Running sleep command which is longer than timeout for context")
		res := vm.ExecContext(ctx, "sleep 10")
		Expect(res.GetError()).Should(Equal(context.DeadlineExceeded))
	})
})

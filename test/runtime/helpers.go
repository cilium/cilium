// Copyright 2018-2019 Authors of Cilium
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
	"context"
	"fmt"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

// TestExecTimeout checks that our SSH execs are able to cancel in-flight
// commands. This is important to avoid blocking CI indefinitely when things
// misbehave.
var _ = Describe("RuntimeTestExecTimeout", func() {
	var vm *helpers.SSHMeta
	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)
	})

	It("Returns from execs on timeout", func() {
		timeout := 10 * time.Second
		sleepSeconds := 20 + (timeout+helpers.CMDGracePeriod)/time.Second
		deadline := time.Now().Add(sleepSeconds * time.Second)

		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()

		res := vm.ExecContext(ctx, fmt.Sprintf("sleep %d", sleepSeconds))
		Expect(res.GetExitCode()).Should(Not(Equal(0)), "Did not interrupt a timed-out exec")
		Expect(!res.WasSuccessful(), "Did not interrupt a timed-out exec")
		Expect(time.Now().Before(deadline), "Did not interrupt a timed-out exec")
	})

	It("Returns from execs on cancel", func() {
		sleepSeconds := 20 + helpers.CMDGracePeriod/time.Second
		deadline := time.Now().Add(1 * time.Second)

		ctx, cancel := context.WithCancel(context.TODO())
		cancel()

		res := vm.ExecContext(ctx, fmt.Sprintf("sleep %d", sleepSeconds))
		Expect(!res.WasSuccessful(), "Did not interrupt a cancelled out exec")
		Expect(res.GetExitCode()).Should(Not(Equal(0)), "Did not interrupt a cancelled out exec")
		Expect(time.Now().Before(deadline), "Did not interrupt a cancelled out exec")
	})
})

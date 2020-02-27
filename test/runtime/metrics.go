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

package RuntimeTest

import (
	"strings"

	"github.com/cilium/cilium/pkg/metrics"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeMetrics", func() {

	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		vm.ReportFailed()
	})

	AfterAll(func() {
		vm.CloseSSHClient()
	})

	Context("Metrics List CLI Test", func() {
		defaultMetrics := metrics.DefaultMetrics()
		supportedMetricKeys := make([]string, len(defaultMetrics))
		i := 0
		for k := range defaultMetrics {
			supportedMetricKeys[i] = k
			i++
		}

		It("test metrics list", func() {
			By("Testing 'cilium metrics list' for existance of all metrics")

			res := vm.Exec(`cilium metrics list`)
			resSingleOut := res.SingleOut()

			for _, metric := range supportedMetricKeys {
				By("checking that metric '%s' is in 'cilium metric list' output", metric)
				containsMetric := strings.Contains(resSingleOut, metric)
				Expect(containsMetric).To(BeTrue(), "metric '%s' not in 'cilium identity list' output", metric)
			}
		})
	})
})

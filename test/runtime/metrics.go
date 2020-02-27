package RuntimeTest

import (
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	metrics "github.com/cilium/cilium/pkg/metrics"
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

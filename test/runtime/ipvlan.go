package RuntimeTest

import (
	"fmt"
	"os"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
)

const ipvlanMasterDevice = "enp0s8"

func failOnErr(ctx string, err error) {
	if err != nil {
		Fail(fmt.Sprintf("%s: %s", ctx, err))
	}
}

func runsOnNetNext() bool {
	return os.Getenv("NETNEXT") == "1"
}

var _ = Describe("RuntimeIpvlanTest", func() {
	var vm *helpers.SSHMeta

	if !runsOnNetNext() {
		Skip("IPVLAN tests can be run only on >= 4.12 kernel")
	}

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

		var config = `
PATH=/usr/lib/llvm-3.8/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
CILIUM_OPTS=--kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug --pprof=true --log-system-load \
	--tunnel=disabled --datapath-mode=ipvlan --ipvlan-master-device=` + ipvlanMasterDevice + `
INITSYSTEM=SYSTEMD`
		err := vm.SetUpCiliumWithOptions(config)
		failOnErr("SetUpCiliumWithOptions", err)
		// cilium-docker has to be restarted because the datapath mode has changed
		vm.Exec("sudo systemctl restart cilium-docker")
		ExpectCiliumReady(vm)
	})

	removeContainer := func(containerName string) {
		By("removing container %s", containerName)
		res := vm.ContainerRm(containerName)
		ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "cannot delete container")
	}

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		vm.ReportFailed()
	})

	Context("Basic IPVLAN Connectivity test", func() {
		BeforeEach(func() {
			vm.ContainerCreate(helpers.Client, constants.NetperfImage,
				helpers.CiliumDockerNetwork, "-l id.client")
			vm.ContainerCreate(helpers.Server, constants.NetperfImage,
				helpers.CiliumDockerNetwork, "-l id.server")
			ready := vm.WaitEndpointsReady()
			if !ready {
				Fail("Endpoints are not ready")
			}

			err := helpers.WithTimeout(func() bool {
				if data, _ := vm.GetEndpointsNames(); len(data) < 2 {
					logger.Info("Waiting for endpoints to be ready")
					return false
				}
				return true
			}, "Endpoints are not ready", &helpers.TimeoutConfig{Timeout: 150})

			Expect(err).Should(BeNil())
		}, 150)

		AfterEach(func() {
			removeContainer(helpers.Client)
			removeContainer(helpers.Server)
			return
		})

		// TODO(brb) DRY with connectivity test
		It("Test connectivity between containers without policies imported", func() {
			// See if we can make the "Filter" strings for getting IPv4 and IPv6 addresses into constants.
			By("inspecting container %s", helpers.Server)
			serverData := vm.ContainerInspect(helpers.Server)
			serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
			Expect(err).Should(BeNil())

			By("serverIP: %q", serverIP)
			serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
			By("serverIPv6: %q", serverIPv6)
			Expect(err).Should(BeNil())

			By("checking %q can ping to %q IPv6", helpers.Client, helpers.Server)
			res := vm.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6.String()))
			res.ExpectSuccess()

			By("checking %q can ping to %q IPv4", helpers.Client, helpers.Server)
			res = vm.ContainerExec(helpers.Client, helpers.Ping(serverIP.String()))
			res.ExpectSuccess()

			// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
			By("netperf to %q from %q IPv6", helpers.Server, helpers.Client)
			cmd := fmt.Sprintf(
				"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)

			res = vm.ContainerExec(helpers.Client, cmd)
			res.ExpectSuccess()
		}, 300)

	})
})

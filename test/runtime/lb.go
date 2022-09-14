// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/gomega"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"
)

var _ = Describe("RuntimeDatapathLB", func() {
	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
		monitorStop   = func() error { return nil }
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)
	})

	AfterAll(func() {
		vm.ServiceDelAll().ExpectSuccess()
		vm.CloseSSHClient()
	})

	JustBeforeEach(func() {
		_, monitorStop = vm.MonitorStart()
		testStartTime = time.Now()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
		Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
	})

	AfterFailed(func() {
		vm.ReportFailed(
			"cilium service list",
			"cilium bpf lb list",
			"cilium policy get")
	})

	images := map[string]string{
		helpers.Httpd1: constants.HttpdImage,
		helpers.Httpd2: constants.HttpdImage,
		helpers.Client: constants.NetperfImage,
	}

	createContainers := func() {
		By("Creating containers for traffic test")

		for k, v := range images {
			res := vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
			res.ExpectSuccess("failed to create container %s", k)
		}
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoint are not ready after timeout")
	}

	deleteContainers := func() {
		for k := range images {
			vm.ContainerRm(k)
		}
	}

	BeforeEach(func() {
		vm.ServiceDelAll().ExpectSuccess()
	}, 500)

	It("validates basic service management functionality", func() {
		result := vm.ServiceAdd(1, "[::]:80", []string{"[::1]:90", "[::2]:91"})
		result.ExpectSuccess("unexpected failure to add service")
		result = vm.ServiceGet(1)
		result.ExpectSuccess("unexpected failure to retrieve service")
		frontendAddress, err := vm.ServiceGetFrontendAddress(1)
		Expect(err).Should(BeNil())
		Expect(frontendAddress).To(ContainSubstring("[::]:80"),
			"failed to retrieve frontend address: %q", result.GetStdOut())

		//TODO: This need to be with Wait,Timeout
		helpers.Sleep(5)

		By("Checking that BPF maps are updated based on service configuration")

		result = vm.ExecCilium("bpf lb list")
		result.ExpectSuccess("bpf lb map cannot be retrieved correctly")
		Expect(result.Stdout()).To(ContainSubstring("[::1]:90"), fmt.Sprintf(
			"service backends not added to BPF map: %q", result.GetStdOut()))

		By("Adding services that should not be allowed")

		result = vm.ServiceAdd(0, "[::]:10000", []string{"[::1]:90", "[::2]:91"})
		result.ExpectFail("unexpected success adding service with id 0")
		result = vm.ServiceAdd(-1, "[::]:10000", []string{"[::1]:90", "[::2]:91"})
		result.ExpectFail("unexpected success adding service with id -1")
		result = vm.ServiceAdd(1, "[::]:10000", []string{"[::1]:90", "[::2]:91"})
		result.ExpectFail("unexpected success adding service with duplicate id 1")
		result = vm.ServiceAdd(2, "10.2.2.2:0", []string{"3.3.3.3:90", "4.4.4.4:91"})
		result.ExpectFail("unexpected success adding service with L3=>L4 redirect")

		By("Adding duplicate service FE address (IPv6)")

		//Trying to create a new service with id 10, that conflicts with the FE addr on id=1
		result = vm.ServiceAdd(10, "[::]:80", []string{"[::1]:90", "[::2]:91"})
		result.ExpectFail("unexpected success adding service with duplicate frontend address (id 10)")
		result = vm.ServiceGet(10)
		result.ExpectFail("unexpected success fetching service with id 10, service should not be present")

		By("Deleting IPv6 service")
		result = vm.ServiceDel(1)
		result.ExpectSuccess("unexpected failure deleting service with id 1")

		By("Creating a valid IPv4 service with id 1")

		result = vm.ServiceAdd(1, "127.0.0.1:80", []string{"127.0.0.1:90", "127.0.0.1:91"})
		result.ExpectSuccess("unexpected failure adding valid service")
		result = vm.ServiceGet(1)
		result.ExpectSuccess("unexpected failure to retrieve service")

		By("Adding duplicate service FE address (IPv4)")

		result = vm.ServiceAdd(20, "127.0.0.1:80", []string{"127.0.0.1:90", "127.0.0.1:91"})
		result.ExpectFail("unexpected success adding service with duplicate frontend address (id 20)")
		result = vm.ServiceGet(20)
		result.ExpectFail("unexpected success fetching service with id 20, service should not be present")
	}, 500)

	It("validates service backend state updates", func() {
		frontend1 := "2.2.2.2:8080"
		frontend2 := "2.2.2.3:8080"
		backend1 := "1.1.1.2:8080"
		backend2 := "1.1.1.3:8080"
		activeState := "active"
		quarantineState := "quarantined"
		type backendCheckTest struct {
			frontend string
			backend  string
			state    string
		}
		getBackendState := func(test backendCheckTest) (bool, error) {
			ip, port, err := net.SplitHostPort(test.frontend)
			if err != nil {
				return false, fmt.Errorf("invalid frontend %s : %s", test.frontend, err)
			}
			portInt, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return false, fmt.Errorf("invalid frontend port %s: %s", test.frontend, err)
			}
			jq := "jq -r '[ .[].status.realized | select(.\"frontend-address\".ip==\"" + ip + "\") | . ]'"
			cmd := "service list -o json | " + jq
			result := vm.ExecCilium(cmd)
			result.ExpectSuccess("failed to find frontend [%s] in service list: %s",
				test.frontend, result.OutputPrettyPrint())
			if strings.TrimSpace(result.Stdout()) == "" {
				return false, fmt.Errorf("frontend %s not found in service list", test.frontend)
			}

			var services []models.ServiceSpec
			err = result.Unmarshal(&services)
			Expect(err).Should(BeNil(), "failed to unmarshal service spec '%s': %s", result.OutputPrettyPrint(), err)

			for _, service := range services {
				if portInt != uint64(service.FrontendAddress.Port) {
					continue
				}

				for _, b := range service.BackendAddresses {
					ba := net.JoinHostPort(*b.IP, fmt.Sprintf("%d", b.Port))
					if ba != test.backend {
						continue
					}
					return b.State == test.state, nil
				}
			}

			return false, fmt.Errorf("failed to get backend %s", test.backend)
		}

		result := vm.ServiceAdd(1, frontend1, []string{backend1, backend2})
		result.ExpectSuccess("unexpected failure to add service")
		result = vm.ExecCilium("bpf lb list")
		result.ExpectSuccess("bpf lb map cannot be retrieved")
		Expect(result.WaitUntilMatch(frontend1), fmt.Sprintf(
			"service backends not added to BPF map: %q", result.GetStdOut()))
		result = vm.ServiceAdd(2, frontend2, []string{backend1, backend2})
		result.ExpectSuccess("unexpected failure to add service")
		result = vm.ExecCilium("bpf lb list")
		result.ExpectSuccess("bpf lb map cannot be retrieved")
		Expect(result.WaitUntilMatch(frontend2), fmt.Sprintf(
			"service backends not added to BPF map: %q", result.GetStdOut()))

		By("Validating default backend states")

		testCases := []backendCheckTest{
			{
				frontend1,
				backend1,
				activeState,
			},
			{
				frontend1,
				backend2,
				activeState,
			},
			{
				frontend2,
				backend1,
				activeState,
			},
			{
				frontend2,
				backend2,
				activeState,
			},
		}

		for _, tc := range testCases {
			matched, err := getBackendState(tc)
			Expect(err).Should(BeNil(), "failed to get backend [%s] state from "+
				"service list %s: %s", backend1, result.OutputPrettyPrint(), err)
			Expect(matched).Should(BeTrue(), "backend [%s] state doesn't match [%s]",
				tc.backend, tc.state)
		}

		By("Validating updated backend states for all services")

		cmd := fmt.Sprintf("service update --backends %s --states %s", backend1, quarantineState)

		result = vm.ExecCilium(cmd)
		result.ExpectSuccess("failed to list cilium services")

		testCases = []backendCheckTest{
			{
				frontend1,
				backend1,
				quarantineState,
			},
			{
				frontend1,
				backend2,
				activeState,
			},
			{
				frontend2,
				backend1,
				quarantineState,
			},
			{
				frontend2,
				backend2,
				activeState,
			},
		}

		for _, tc := range testCases {
			matched, err := getBackendState(tc)
			Expect(err).Should(BeNil(), "unable to get backend [%s] state from "+
				"service list %s: %s", backend1, result.OutputPrettyPrint(), err)
			Expect(matched).Should(BeTrue(), "backend [%s] state doesn't match [%s]",
				tc.backend, tc.state)
		}

		By("Validating restored backend states for all services after restart")

		err := vm.RestartCilium()
		Expect(err).Should(BeNil(), "restarting Cilium failed")

		for _, tc := range testCases {
			matched, err := getBackendState(tc)
			Expect(err).Should(BeNil(), "unable to get backend [%s] state from "+
				"service list %s: %s", backend1, result.OutputPrettyPrint(), err)
			Expect(matched).Should(BeTrue(), "backend [%s] state doesn't match [%s]",
				tc.backend, tc.state)
		}
	})

	Context("With Containers", func() {

		BeforeAll(func() {
			createContainers()
		})

		AfterAll(func() {
			deleteContainers()
		})

		It("validates service recovery on restart", func() {
			service := "10.2.2.2:80"
			svcID := 1
			testCmd := helpers.CurlFail(fmt.Sprintf("http://%s/public", service))

			httpd1, err := vm.ContainerInspectNet("httpd1")
			Expect(err).Should(BeNil())
			httpd2, err := vm.ContainerInspectNet("httpd2")
			Expect(err).Should(BeNil())

			status := vm.ServiceAdd(svcID, service, []string{
				net.JoinHostPort(httpd1["IPv4"], "80"),
				net.JoinHostPort(httpd2["IPv4"], "80")})
			status.ExpectSuccess("failed to create service %s=>{httpd1,httpd2}", service)

			By("Making HTTP request via the service before restart")

			status = vm.ContainerExec(helpers.Client, testCmd)
			status.ExpectSuccess("Failed to fetch URL via service")
			oldSvc := vm.ServiceList()
			oldSvc.ExpectSuccess("Cannot retrieve service list")

			By("Fetching service state before restart")

			oldSvcIds, err := vm.ServiceGetIds()
			Expect(err).Should(BeNil())
			oldBpfLB, err := vm.BpfLBList(false)
			Expect(err).Should(BeNil())

			err = vm.RestartCilium()
			Expect(err).Should(BeNil(), "restarting Cilium failed")

			By("Checking that the service was restored correctly")

			svcIds, err := vm.ServiceGetIds()
			Expect(err).Should(BeNil())
			Expect(len(svcIds)).Should(Equal(len(oldSvcIds)),
				"Service ids %s do not match old service ids %s", svcIds, oldSvcIds)
			newSvc := vm.ServiceList()
			newSvc.ExpectSuccess("Cannot retrieve service list after restart")
			newSvc.ExpectEqual(oldSvc.Stdout(), "Service list does not match")

			By("Checking that BPF LB maps match the service")

			newBpfLB, err := vm.BpfLBList(false)
			Expect(err).Should(BeNil(), "Cannot retrieve bpf lb list after restart")
			Expect(oldBpfLB).Should(Equal(newBpfLB))
			svcSync, err := vm.ServiceIsSynced(svcID)
			Expect(err).Should(BeNil(), "Service is not sync with BPF LB")
			Expect(svcSync).Should(BeTrue())

			By("Making HTTP request via the service after restart")

			status = vm.ContainerExec("client", testCmd)
			status.ExpectSuccess("Failed to fetch URL via service")
		})
	})

	Context("Services Policies", func() {

		BeforeAll(func() {
			vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		})

		AfterAll(func() {
			vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
		})

		AfterEach(func() {
			vm.PolicyDelAll().ExpectSuccess()
			vm.ServiceDelAll().ExpectSuccess()

			status := vm.ExecCilium(fmt.Sprintf("config %s=false",
				helpers.OptionConntrackLocal))
			status.ExpectSuccess()
		})

		testServicesWithPolicies := func(svcPort int) {
			Expect(vm.WaitEndpointsReady()).To(BeTrue(), "Endpoint are not ready after timeout")

			httpd1, err := vm.ContainerInspectNet(helpers.Httpd1)
			Expect(err).Should(BeNil())
			httpd2, err := vm.ContainerInspectNet(helpers.Httpd2)
			Expect(err).Should(BeNil())

			By("Configuring services")

			service1 := net.JoinHostPort("10.2.2.100", fmt.Sprintf("%d", svcPort))
			service2 := net.JoinHostPort("f00d::1:1", fmt.Sprintf("%d", svcPort))
			service3 := net.JoinHostPort("10.2.2.101", fmt.Sprintf("%d", svcPort))
			services := map[string]string{
				service1: net.JoinHostPort(httpd1[helpers.IPv4], "80"),
				service2: net.JoinHostPort(httpd2[helpers.IPv6], "80"),
				service3: net.JoinHostPort(httpd2[helpers.IPv4], "80"),
			}
			svc := 100
			for fe, be := range services {
				status := vm.ServiceAdd(svc, fe, []string{be})
				status.ExpectSuccess(fmt.Sprintf("failed to create service %s=>%s", fe, be))
				svc++
			}

			getHTTP := func(service, target string) string {
				return helpers.CurlFail(fmt.Sprintf(
					"http://%s/%s", service, target))
			}

			_, err = vm.PolicyImportAndWait(vm.GetFullPath(policiesL7JSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			By("Making HTTP request to service with ingress policy")

			status := vm.ContainerExec(helpers.App1, getHTTP(service1, helpers.Public))
			status.ExpectSuccess()
			status = vm.ContainerExec(helpers.App3, getHTTP(service1, helpers.Public))
			status.ExpectFail()

			By("Making HTTP request via egress policy to service IP")

			status = vm.ContainerExec(helpers.App2, getHTTP(service2, helpers.Public))
			status.ExpectSuccess()
			status = vm.ContainerExec(helpers.App2, getHTTP(service2, helpers.Private))
			status.ExpectFail()
			status = vm.ContainerExec(helpers.App2, getHTTP(service3, helpers.Public))
			status.ExpectSuccess()

			By("Making HTTP requests to service with multiple ingress policies")

			vm.PolicyDelAll()
			_, err = vm.PolicyImportAndWait(vm.GetFullPath(multL7PoliciesJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			status = vm.ContainerExec(helpers.App1, getHTTP(service1, helpers.Public))
			status.ExpectSuccess()
			status = vm.ContainerExec(helpers.App1, getHTTP(service1, helpers.Private))
			status.ExpectFail()
			status = vm.ContainerExec(helpers.App3, getHTTP(service1, helpers.Public))
			status.ExpectFail()

			By("Making HTTP requests via multiple egress policies to service IP")

			status = vm.ContainerExec(helpers.App2, getHTTP(service2, helpers.Public))
			status.ExpectSuccess()
			status = vm.ContainerExec(helpers.App2, getHTTP(service2, helpers.Private))
			status.ExpectFail()
			status = vm.ContainerExec(helpers.App2, getHTTP(service3, helpers.Public))
			status.ExpectSuccess()
		}

		It("tests with conntrack enabled", func() {
			status := vm.ExecCilium(fmt.Sprintf("config %s=true",
				helpers.OptionConntrackLocal))
			status.ExpectSuccess()
			testServicesWithPolicies(80)
		})

		It("tests with conntrack disabled", func() {
			status := vm.ExecCilium(fmt.Sprintf("config %s=false",
				helpers.OptionConntrackLocal))
			status.ExpectSuccess()
			testServicesWithPolicies(80)
		})

		/* Policy is written against egress to port 80, so when an
		 * app makes requests on port 1234, the service translation
		 * should occur before applying the egress policy.
		 */
		It("tests with service performing L4 port mapping", func() {
			testServicesWithPolicies(1234)
		})
	})
})

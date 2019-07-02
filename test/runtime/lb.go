// Copyright 2017-2019 Authors of Cilium
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
	"os"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeLB", func() {
	var (
		vm          *helpers.SSHMeta
		monitorStop = func() error { return nil }
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
		monitorStop = vm.MonitorStart()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
	})

	AfterFailed(func() {
		vm.ReportFailed(
			"cilium service list",
			"cilium bpf lb list",
			"cilium policy get")
	})

	AfterEach(func() {
		cleanupLBDevice(vm)
	}, 500)

	images := map[string]string{
		helpers.Httpd1: constants.HttpdImage,
		helpers.Httpd2: constants.HttpdImage,
		helpers.Client: constants.NetperfImage,
	}

	createContainers := func() {
		By("Creating containers for traffic test")

		for k, v := range images {
			vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
		}
		epStatus := vm.WaitEndpointsReady()
		Expect(epStatus).Should(BeTrue())
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
			"failed to retrieve frontend address: %q", result.Output())

		//TODO: This need to be with Wait,Timeout
		helpers.Sleep(5)

		By("Checking that BPF maps are updated based on service configuration")

		result = vm.ExecCilium("bpf lb list")
		result.ExpectSuccess("bpf lb map cannot be retrieved correctly")
		Expect(result.Output()).To(ContainSubstring("[::1]:90"), fmt.Sprintf(
			"service backends not added to BPF map: %q", result.Output()))

		By("Adding services that should not be allowed")

		result = vm.ServiceAdd(0, "[::]:10000", []string{"[::1]:90", "[::2]:91"})
		result.ExpectFail("unexpected success adding service with id 0")
		result = vm.ServiceAdd(-1, "[::]:10000", []string{"[::1]:90", "[::2]:91"})
		result.ExpectFail("unexpected success adding service with id -1")
		result = vm.ServiceAdd(1, "[::]:10000", []string{"[::1]:90", "[::2]:91"})
		result.ExpectFail("unexpected success adding service with duplicate id 1")
		result = vm.ServiceAdd(2, "2.2.2.2:0", []string{"3.3.3.3:90", "4.4.4.4:91"})
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

	Context("With Containers", func() {

		BeforeAll(func() {
			createContainers()
		})

		AfterAll(func() {
			deleteContainers()
		})

		It("validates that services work for L3 (IP) loadbalancing", func() {
			err := createLBDevice(vm)
			if err != nil {
				log.Errorf("error creating interface: %s", err)
			}
			Expect(err).Should(BeNil())

			httpd1, err := vm.ContainerInspectNet(helpers.Httpd1)
			Expect(err).Should(BeNil())
			httpd2, err := vm.ContainerInspectNet(helpers.Httpd2)
			Expect(err).Should(BeNil())

			By("Creating services")

			services := map[string][]string{
				"2.2.2.2:0": {
					fmt.Sprintf("%s:0", httpd1[helpers.IPv4]),
					fmt.Sprintf("%s:0", httpd2[helpers.IPv4]),
				},
				"[f00d::1:1]:0": {
					fmt.Sprintf("[%s]:0", httpd1[helpers.IPv6]),
					fmt.Sprintf("[%s]:0", httpd2[helpers.IPv6]),
				},
				"3.3.3.3:0": {
					fmt.Sprintf("%s:0", "10.0.2.15"),
				},
				"[f00d::1:2]:0": {
					fmt.Sprintf("[%s]:0", "fd02:1:1:1:1:1:1:1"),
				},
			}
			svc := 1
			for fe, be := range services {
				status := vm.ServiceAdd(svc, fe, be)
				status.ExpectSuccess(fmt.Sprintf("failed to create service %s=>%v", fe, be))
				svc++
			}

			By("Pinging host => bpf_lb => container")

			status := vm.Exec(helpers.Ping("2.2.2.2"))
			status.ExpectSuccess("failed to ping service IP from host")
			// FIXME GH-2889: createLBDevice() doesn't configure host IPv6
			//status = vm.Exec(helpers.Ping6("f00d::1:1"))
			//status.ExpectSuccess("failed to ping service IP from host")

			By("Pinging container => bpf_lb => container")

			status = vm.ContainerExec(helpers.Client, helpers.Ping("2.2.2.2"))
			status.ExpectSuccess("failed to ping service IP 2.2.2.2")
			status = vm.ContainerExec(helpers.Client, helpers.Ping6("f00d::1:1"))
			status.ExpectSuccess("failed to ping service IP f00d::1:1")

			By("Pinging container => bpf_lb => host")

			status = vm.ContainerExec(helpers.Client, helpers.Ping("3.3.3.3"))
			status.ExpectSuccess("failed to ping service IP 3.3.3.3")
			status = vm.ContainerExec(helpers.Client, helpers.Ping("f00d::1:2"))
			status.ExpectSuccess("failed to ping service IP f00d::1:2")

			By("Configuring services to point to own IP via service")

			vm.ServiceDelAll().ExpectSuccess()
			loopbackServices := map[string]string{
				"2.2.2.2:0":     fmt.Sprintf("%s:0", httpd1[helpers.IPv4]),
				"[f00d::1:1]:0": fmt.Sprintf("[%s]:0", httpd1[helpers.IPv6]),
			}
			svc = 1
			for fe, be := range loopbackServices {
				status := vm.ServiceAdd(svc, fe, []string{be})
				status.ExpectSuccess(fmt.Sprintf("failed to create service %s=>%v", fe, be))
				svc++
			}

			By("Pinging from server1 to its own service IP")

			status = vm.ContainerExec(helpers.Httpd1, helpers.Ping("2.2.2.2"))
			status.ExpectSuccess("failed to ping service IP 2.2.2.2")
			status = vm.ContainerExec(helpers.Httpd1, helpers.Ping6("f00d::1:1"))
			status.ExpectSuccess("failed to ping service IP f00d::1:1")
		}, 500)

		It("validates that services work for L4 (IP+Port) loadbalancing", func() {
			err := createLBDevice(vm)
			if err != nil {
				log.Errorf("error creating interface: %s", err)
			}
			Expect(err).Should(BeNil())

			httpd1, err := vm.ContainerInspectNet(helpers.Httpd1)
			Expect(err).Should(BeNil())
			httpd2, err := vm.ContainerInspectNet(helpers.Httpd2)
			Expect(err).Should(BeNil())

			By("Creating services")

			services := map[string][]string{
				"2.2.2.2:80": {
					fmt.Sprintf("%s:80", httpd1[helpers.IPv4]),
					fmt.Sprintf("%s:80", httpd2[helpers.IPv4]),
				},
				"[f00d::1:1]:80": {
					fmt.Sprintf("[%s]:80", httpd1[helpers.IPv6]),
					fmt.Sprintf("[%s]:80", httpd2[helpers.IPv6]),
				},
			}
			svc := 1
			for fe, be := range services {
				status := vm.ServiceAdd(svc, fe, be)
				status.ExpectSuccess("failed to create service %s=>%v", fe, be)
				svc++
			}

			By("Making HTTP requests from container => bpf_lb => container")

			for ip := range services {
				url := fmt.Sprintf("http://%s/public", ip)
				status := vm.ContainerExec(helpers.Client, helpers.CurlFail(url))
				status.ExpectSuccess(fmt.Sprintf("failed to fetch via URL %s", url))
			}
		}, 500)

		It("validates service recovery on restart", func() {
			service := "2.2.2.2:80"
			svcID := 1
			testCmd := helpers.CurlFail(fmt.Sprintf("http://%s/public", service))

			httpd1, err := vm.ContainerInspectNet("httpd1")
			Expect(err).Should(BeNil())
			httpd2, err := vm.ContainerInspectNet("httpd2")
			Expect(err).Should(BeNil())

			status := vm.ServiceAdd(svcID, service, []string{
				fmt.Sprintf("%s:80", httpd1["IPv4"]),
				fmt.Sprintf("%s:80", httpd2["IPv4"])})
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
			newSvc.ExpectEqual(oldSvc.Output().String(), "Service list does not match")

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
			ready := vm.WaitEndpointsReady()
			Expect(ready).To(BeTrue())

			httpd1, err := vm.ContainerInspectNet(helpers.Httpd1)
			Expect(err).Should(BeNil())
			httpd2, err := vm.ContainerInspectNet(helpers.Httpd2)
			Expect(err).Should(BeNil())

			By("Configuring services")

			service1 := fmt.Sprintf("2.2.2.100:%d", svcPort)
			service2 := fmt.Sprintf("[f00d::1:1]:%d", svcPort)
			service3 := fmt.Sprintf("2.2.2.101:%d", svcPort)
			services := map[string]string{
				service1: fmt.Sprintf("%s:80", httpd1[helpers.IPv4]),
				service2: fmt.Sprintf("[%s]:80", httpd2[helpers.IPv6]),
				service3: fmt.Sprintf("%s:80", httpd2[helpers.IPv4]),
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

// createLBDevice instantiates a device with the bpf_lb program to handle
// loadbalancing as though it were attached to a physical device on the system.
// This is implemented through a veth pair with two ends, lbtest1 and lbtest2.
// bpf_lb is attached to ingress at lbtest2, so when traffic is sent through
// lbtest1 it is forwarded through the veth pair into lbtest2 where the BPF
// program executes the services functionality.
//
// The following traffic is routed to lbtest1 (so it goes to the LB BPF prog):
// * 3.3.3.3/32
// * 2.2.2.2/32
// * f00d:1:1/128
// * fbfb::10:10/128
//
// Additionally, the following IPs are associated with the cilium_host device,
// so they may be used as backends for services and they will receive a
// response from the host:
// * 10.0.2.15 (inherited from virtualbox VM configuration)
// * fd02:1:1:1:1:1:1:1 (explicitly configured below)
func createLBDevice(node *helpers.SSHMeta) error {
	script := `#!/bin/bash
function mac2array() {
    echo "{0x${1//:/,0x}}"
}

ip link add lbtest1 type veth peer name lbtest2
ip link set lbtest1 up

# Route f00d::1:1 IPv6 packets to a fantasy router ("fbfb::10:10") behind lbtest1
ip -6 route add fbfb::10:10/128 dev lbtest1
MAC=$(ip link show lbtest1 | grep ether | awk '{print $2}')
ip neigh add fbfb::10:10 lladdr $MAC dev lbtest1
ip -6 route add f00d::1:1/128 via fbfb::10:10

# Route 2.2.2.2 IPv4 packets to a fantasy router ("3.3.3.3") behind lbtest1
ip route add 3.3.3.3/32 dev lbtest1
MAC=$(ip link show lbtest1 | grep ether | awk '{print $2}')
ip neigh add 3.3.3.3 lladdr $MAC dev lbtest1
ip route add 2.2.2.2/32 via 3.3.3.3

ip link set lbtest2 up

LIB=/var/lib/cilium/bpf
RUN=/var/run/cilium/state
NH_IFINDEX=$(cat /sys/class/net/cilium_host/ifindex)
NH_MAC=$(ip link show cilium_host | grep ether | awk '{print $2}')
NH_MAC="{.addr=$(mac2array $NH_MAC)}"
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -DLB_L3 -DLB_REDIRECT=$NH_IFINDEX -DLB_DSTMAC=$NH_MAC -DCALLS_MAP=lbtest -O2 -target bpf -I. -I$LIB -I$LIB/include -I$RUN/globals -DDEBUG -Wno-address-of-packed-member -Wno-unknown-warning-option"
touch netdev_config.h
clang $CLANG_OPTS -c $LIB/bpf_lb.c -o tmp_lb.o

tc qdisc del dev lbtest2 clsact 2> /dev/null || true
tc qdisc add dev lbtest2 clsact
tc filter add dev lbtest2 ingress bpf da obj tmp_lb.o sec from-netdev
`
	By("Creating LB device to handle service requests")
	scriptName := "create_veth_interface"
	log.Infof("generating veth script: %s", scriptName)
	err := helpers.RenderTemplateToFile(scriptName, script, os.ModePerm)
	if err != nil {
		return err
	}

	// filesystem is mounted at path /vagrant on VM
	scriptPath := fmt.Sprintf("%s/%s", helpers.BasePath, scriptName)

	ipAddrCmd := "sudo ip addr add fd02:1:1:1:1:1:1:1 dev cilium_host"
	res := node.Exec(ipAddrCmd)
	log.Infof("output of %q: %s", ipAddrCmd, res.CombineOutput())

	log.Infof("running script %s", scriptPath)
	runScriptCmd := fmt.Sprintf("sudo %s", scriptPath)
	res = node.Exec(runScriptCmd)
	log.Infof("output of %q: %s", runScriptCmd, res.CombineOutput())
	log.Infof("removing file %q", scriptName)
	err = os.Remove(scriptName)
	return err
}

func cleanupLBDevice(node *helpers.SSHMeta) {
	ipAddrCmd := "sudo ip addr del fd02:1:1:1:1:1:1:1/128 dev cilium_host"
	res := node.Exec(ipAddrCmd)
	log.Infof("output of %q: %s", ipAddrCmd, res.CombineOutput())

	ipLinkCmd := "sudo ip link del dev lbtest1"
	res = node.Exec(ipLinkCmd)
	log.Infof("output of %q: %s", ipLinkCmd, res.CombineOutput())
}

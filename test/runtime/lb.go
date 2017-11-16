// Copyright 2017 Authors of Cilium
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

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeLB", func() {

	var initialized bool
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"test": "RuntimeLB"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		cilium.WaitUntilReady(100)
		docker.NetworkCreate(helpers.CiliumDockerNetwork, "")
		initialized = true
	}

	// TODO: rename this function; its name is not clear.
	containers := func(mode string) {
		images := map[string]string{
			helpers.Httpd1: helpers.HttpdImage,
			helpers.Httpd2: helpers.HttpdImage,
			helpers.Httpd3: helpers.HttpdImage,
			helpers.Client: helpers.NetperfImage,
		}

		switch mode {
		case helpers.Create:
			for k, v := range images {
				docker.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
			}
		case helpers.Delete:
			for k := range images {
				docker.ContainerRm(k)
			}
		}
	}

	BeforeEach(func() {
		initialize()
		cilium.Exec("service delete --all")
	}, 500)

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed(
				"sudo cilium service list",
				"sudo cilium endpoint list")
		}
		containers(helpers.Delete)
	}, 500)

	It("Service Simple tests", func() {

		By("Creating a valid service")
		result := cilium.ServiceAdd(1, "[::]:80", []string{"[::1]:90", "[::2]:91"}, 2)

		result.ExpectSuccess("Service can't be added in cilium")

		result = cilium.ServiceGet(1)
		result.ExpectSuccess("Service cannot be retrieved correctly")

		Expect(result.Output()).Should(ContainSubstring("[::1]:90"), fmt.Sprintf(
			"No service backends added correctly %q", result.Output()))
		helpers.Sleep(5)
		//TODO: This need to be with Wait,Timeout
		//Checking that bpf lb list is working correctly
		result = cilium.Exec("bpf lb list")

		result.ExpectSuccess("service cannot be retrieved correctly")

		Expect(result.Output()).Should(ContainSubstring("[::1]:90"), fmt.Sprintf(
			"No service backends added correctly %q", result.Output()))

		By("Service ID 0")
		result = cilium.ServiceAdd(0, "[::]:10000", []string{"[::1]:90", "[::2]:91"}, 2)
		result.ExpectFail("Service with id 0 can be added in cilium")

		By("Service ID -1")
		result = cilium.ServiceAdd(-1, "[::]:10000", []string{"[::1]:90", "[::2]:91"}, 2)
		result.ExpectFail("Service with id -1 can be added in cilium")

		By("Duplicating serviceID")
		result = cilium.ServiceAdd(1, "[::]:10000", []string{"[::1]:90", "[::2]:91"}, 2)
		result.ExpectFail("Service with duplicated id can be added in cilium")

		By("Duplicating service FE address")
		//Trying to create a new service with id 10, that conflicts with the FE addr on id=1
		result = cilium.ServiceAdd(10, "[::]:80", []string{"[::1]:90", "[::2]:91"}, 2)
		result.ExpectFail("Service with duplicated FE can be added in cilium")

		result = cilium.ServiceGet(10)
		result.ExpectFail("service was added; addition of said service should have failed")

		//Deleting service ID=1
		result = cilium.ServiceDel(1)
		result.ExpectSuccess("Service cannot be deleted")

		By("IPv4 testing")
		result = cilium.ServiceAdd(1, "127.0.0.1:80", []string{"127.0.0.1:90", "127.0.0.1:91"}, 2)

		Expect(result.WasSuccessful()).Should(BeTrue(),
			"Service cannot be added in cilium")

		result = cilium.ServiceGet(1)
		result.ExpectSuccess("Service cannot be retrieved correctly")

		By("Duplicating service FE address IPv4")
		result = cilium.ServiceAdd(20, "127.0.0.1:80", []string{"127.0.0.1:90", "127.0.0.1:91"}, 2)
		result.ExpectFail("Service can be added in cilium with duplicated FE")

		result = cilium.ServiceGet(20)
		result.ExpectFail("Service was added and it shouldn't")
	}, 500)

	It("Service L3 tests", func() {
		err := createInterface(docker.Node)
		if err != nil {
			log.Errorf("error creating interface: %s", err)
		}
		Expect(err).Should(BeNil())

		containers(helpers.Create)

		httpd1, err := docker.ContainerInspectNet(helpers.Httpd1)
		Expect(err).Should(BeNil())

		httpd2, err := docker.ContainerInspectNet(helpers.Httpd2)
		Expect(err).Should(BeNil())

		//Create all the services

		cilium.ServiceAdd(1, "2.2.2.2:0", []string{
			fmt.Sprintf("%s:0", httpd1[helpers.IPv4]),
			fmt.Sprintf("%s:0", httpd2[helpers.IPv4])}, 2)

		cilium.ServiceAdd(2, "[f00d::1:1]:0", []string{
			fmt.Sprintf("[%s]:0", httpd1[helpers.IPv6]),
			fmt.Sprintf("[%s]:0", httpd2[helpers.IPv6])}, 100)

		cilium.ServiceAdd(11, "3.3.3.3:0", []string{
			fmt.Sprintf("%s:0", "10.0.2.15")}, 100)

		cilium.ServiceAdd(22, "[f00d::1:2]:0", []string{
			fmt.Sprintf("[%s]:0", "fd02:1:1:1:1:1:1:1")}, 100)

		By("Cilium L3 service with Ipv4")

		status := docker.ContainerExec(helpers.Client, helpers.Ping("2.2.2.2"))
		status.ExpectSuccess("L3 Proxy is not working IPv4")

		By("Cilium L3 service with Ipv6")
		status = docker.ContainerExec(helpers.Client, helpers.Ping6("f00d::1:1"))
		status.ExpectSuccess("L3 Proxy is not working IPv6")

		By("Cilium L3 service with Ipv4 Reverse")
		status = docker.ContainerExec(helpers.Client, helpers.Ping("3.3.3.3"))
		status.ExpectSuccess("L3 Proxy is not working IPv6")

		By("Cilium L3 service with Ipv6 Reverse")
		status = docker.ContainerExec(helpers.Client, helpers.Ping("f00d::1:2"))
		status.ExpectSuccess("L3 Proxy is not working IPv6")
	}, 500)

	It("Service L4 tests", func() {
		err := createInterface(docker.Node)
		if err != nil {
			log.Errorf("error creating interface: %s", err)
		}
		Expect(err).Should(BeNil())

		containers(helpers.Create)
		cilium.WaitEndpointsReady()

		httpd1, err := docker.ContainerInspectNet(helpers.Httpd1)
		Expect(err).Should(BeNil())

		httpd2, err := docker.ContainerInspectNet(helpers.Httpd2)
		Expect(err).Should(BeNil())

		By("Valid IPV4 nat")
		status := cilium.ServiceAdd(1, "2.2.2.2:80", []string{
			fmt.Sprintf("%s:80", httpd1[helpers.IPv4]),
			fmt.Sprintf("%s:80", httpd2[helpers.IPv4])}, 2)
		status.ExpectSuccess("L4 service cannot be created")

		status = docker.ContainerExec(
			helpers.Client,
			helpers.CurlFail("http://2.2.2.2:80/public"))
		status.ExpectSuccess("L4 Proxy is not working IPv4")

		By("Valid IPV6 nat")
		status = cilium.ServiceAdd(2, "[f00d::1:1]:80", []string{

			fmt.Sprintf("[%s]:80", httpd1[helpers.IPv6]),
			fmt.Sprintf("[%s]:80", httpd2[helpers.IPv6])}, 2)
		status.ExpectSuccess("L4 service cannot be created")

		status = docker.ContainerExec(
			helpers.Client,
			helpers.CurlFail("http://2.2.2.2:80/public"))
		status.ExpectSuccess("L4 Proxy is not working IPv6")

		By("L3 redirect to L4")
		status = cilium.ServiceAdd(3, "2.2.2.2:0", []string{

			fmt.Sprintf("%s:80", httpd1[helpers.IPv4]),
			fmt.Sprintf("%s:80", httpd2[helpers.IPv4])}, 2)
		status.ExpectFail("Service created with invalid data")
	}, 500)

	It("Service recovery on restart", func() {
		containers("create")
		cilium.EndpointWaitUntilReady()

		httpd1, err := docker.ContainerInspectNet("httpd1")
		Expect(err).Should(BeNil())

		httpd2, err := docker.ContainerInspectNet("httpd2")
		Expect(err).Should(BeNil())

		status := cilium.ServiceAdd(1, "2.2.2.2:80", []string{
			fmt.Sprintf("%s:80", httpd1["IPv4"]),
			fmt.Sprintf("%s:80", httpd2["IPv4"])}, 2)
		status.ExpectSuccess("L4 service can't be created")

		status = docker.ContainerExec(
			"client",
			"curl -s --fail --connect-timeout 4 http://2.2.2.2:80/public")
		status.ExpectSuccess("L4 Proxy is not working IPv4")

		oldSvc := cilium.ServiceList()
		oldSvc.ExpectSuccess("Cannot retrieve service list")

		oldSvcIds, err := cilium.ServiceGetIds()
		Expect(err).Should(BeNil())

		oldbpflb := cilium.Exec("bpf lb list -o json")
		oldbpflb.ExpectSuccess()

		res := cilium.Node.Exec("sudo systemctl restart cilium")
		res.ExpectSuccess()

		err = cilium.WaitUntilReady(100)
		Expect(err).Should(BeNil())

		eps := cilium.EndpointWaitUntilReady()
		Expect(eps).Should(BeTrue())

		svcIds, err := cilium.ServiceGetIds()
		Expect(err).Should(BeNil())
		Expect(len(svcIds)).Should(Equal(len(oldSvcIds)), "Service recovery does not match")

		newSvc := cilium.ServiceList()
		newSvc.ExpectSuccess("Cannot retrieve service list after restart")
		newSvc.ExpectEqual(oldSvc.Output().String(), "Service list does not match")

		newBpflb := cilium.Exec("bpf lb list -o json")
		newBpflb.ExpectSuccess("Cannot retrieve bpf lb list after restart")
		newBpflb.ExpectEqual(oldbpflb.Output().String(), "BPF LB list does not match")

		status = docker.ContainerExec(
			"client",
			"curl -s --fail --connect-timeout 4 http://2.2.2.2:80/public")
		status.ExpectSuccess("LB is not working after restart")
	})
})

func createInterface(node *helpers.SSHMeta) error {
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
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -DLB_L3 -DLB_REDIRECT=$NH_IFINDEX -DLB_DSTMAC=$NH_MAC -DCALLS_MAP=lbtest -O2 -target bpf -I. -I$LIB/include -I$RUN/globals -DDEBUG -Wno-address-of-packed-member -Wno-unknown-warning-option"
touch netdev_config.h
clang $CLANG_OPTS -c $LIB/bpf_lb.c -o tmp_lb.o

tc qdisc del dev lbtest2 clsact 2> /dev/null || true
tc qdisc add dev lbtest2 clsact
tc filter add dev lbtest2 ingress bpf da obj tmp_lb.o sec from-netdev
`
	scriptName := "create_veth_interface"
	log.Infof("generating veth script: %s", scriptName)
	err := helpers.RenderTemplateToFile(scriptName, script, os.ModePerm)
	if err != nil {
		return err
	}

	// filesystem is mounted at path /vagrant on VM
	scriptPath := fmt.Sprintf("%s%s", helpers.BasePath, scriptName)

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

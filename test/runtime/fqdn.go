// Copyright 2018 Authors of Cilium
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
	"path/filepath"
	"time"

	"github.com/cilium/cilium/pkg/fqdn"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var bindCiliumTestTemplate = `
$TTL 3
$ORIGIN cilium.test.

@       IN      SOA     cilium.test. admin.cilium.test. (
                        200608081       ; serial, todays date + todays serial #
                        8H              ; refresh, seconds
                        2H              ; retry, seconds
                        4W              ; expire, seconds
                        1D )            ; minimum, seconds
;
;
@               IN NS server
server.cilium.test. IN A 127.0.0.1

world1.cilium.test. IN A %[1]s
world2.cilium.test. IN A %[2]s
world3.cilium.test. IN A %[3]s

roundrobin.cilium.test.    1   IN   A %[1]s
roundrobin.cilium.test.    1   IN   A %[2]s
roundrobin.cilium.test.    1   IN   A %[3]s
`

var bindOutsideTestTemplate = `
$TTL 3
$ORIGIN outside.test.

@       IN      SOA     outside.test. admin.outside.test. (
                        200608081       ; serial, todays date + todays serial #
                        8H              ; refresh, seconds
                        2H              ; retry, seconds
                        4W              ; expire, seconds
                        1D )            ; minimum, seconds
;
;
@               IN NS server
server.outside.test. IN A 127.0.0.1

world1.outside.test. IN A %[1]s
world2.outside.test. IN A %[2]s
world3.outside.test. IN A %[3]s
`

var bind9ZoneConfig = `
zone "cilium.test" {
        type master;
        file "/etc/bind/db.cilium.test";
};

zone "outside.test" {
        type master;
        file "/etc/bind/db.outside.test";
};
`

var _ = Describe("RuntimeFQDNPolicies", func() {
	const (
		bindContainerImage = "docker.io/cilium/docker-bind:v0.1"
		bindContainerName  = "bind"
		worldNetwork       = "world"
		WorldHttpd1        = "WorldHttpd1"
		WorldHttpd2        = "WorldHttpd2"
		WorldHttpd3        = "WorldHttpd3"

		bindDBCilium     = "db.cilium.test"
		bindDBOutside    = "db.outside.test"
		bindNamedConf    = "named.conf.local"
		bindNamedOptions = "named.conf.options"
	)

	var (
		vm          *helpers.SSHMeta
		monitorStop = func() error { return nil }

		ciliumTestImages = map[string]string{
			WorldHttpd1: helpers.HttpdImage,
			WorldHttpd2: helpers.HttpdImage,
			WorldHttpd3: helpers.HttpdImage,
		}

		ciliumOutisdeImages = map[string]string{
			WorldHttpd1: helpers.HttpdImage,
			WorldHttpd2: helpers.HttpdImage,
			WorldHttpd3: helpers.HttpdImage,
		}

		worldIps       = map[string]string{}
		outsideIps     = map[string]string{}
		generatedFiles = []string{bindDBCilium, bindNamedConf, bindDBOutside}
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)

		By("Create sample containers in %q docker network", worldNetwork)
		vm.Exec(fmt.Sprintf("docker network create  %s", worldNetwork)).ExpectSuccess(
			"%q network cant be created", worldNetwork)

		for name, image := range ciliumTestImages {
			vm.ContainerCreate(name, image, worldNetwork, fmt.Sprintf("-l id.%s", name))
			res := vm.ContainerInspect(name)
			res.ExpectSuccess("Container is not ready after create it")
			ip, err := res.Filter(fmt.Sprintf(`{[0].NetworkSettings.Networks.%s.IPAddress}`, worldNetwork))
			Expect(err).To(BeNil(), "Cannot retrieve network info for %q", name)
			worldIps[name] = ip.String()
		}

		bindConfig := fmt.Sprintf(bindCiliumTestTemplate, getMapValues(worldIps)...)
		err := helpers.RenderTemplateToFile(bindDBCilium, bindConfig, os.ModePerm)
		Expect(err).To(BeNil(), "bind file can't be created")

		for name, image := range ciliumOutisdeImages {
			vm.ContainerCreate(name, image, worldNetwork, fmt.Sprintf("-l id.%s", name))
			res := vm.ContainerInspect(name)
			res.ExpectSuccess("Container is not ready after create it")
			ip, err := res.Filter(fmt.Sprintf(`{[0].NetworkSettings.Networks.%s.IPAddress}`, worldNetwork))
			Expect(err).To(BeNil(), "Cannot retrieve network info for %q", name)
			outsideIps[name] = ip.String()
		}
		bindConfig = fmt.Sprintf(bindOutsideTestTemplate, getMapValues(outsideIps)...)
		err = helpers.RenderTemplateToFile(bindDBOutside, bindConfig, os.ModePerm)
		Expect(err).To(BeNil(), "bind file can't be created")

		err = helpers.RenderTemplateToFile(bindNamedConf, bind9ZoneConfig, os.ModePerm)
		Expect(err).To(BeNil(), "Bind named.conf  local file can't be created")

		vm.ExecWithSudo("mkdir -m777 -p /data")
		for _, file := range generatedFiles {
			vm.Exec(fmt.Sprintf("mv %s /data/%s",
				filepath.Join(helpers.BasePath, file), file)).ExpectSuccess(
				"Cannot copy %q to bind container", file)
		}

		By("Setting up bind container")
		// Use a bridge network (The docker default) to be able to use this
		// server from cilium agent. This should change when DNS proxy is in
		// place.
		res := vm.ContainerCreate(
			bindContainerName,
			bindContainerImage,
			"bridge",
			"-p 53:53/udp -p 53:53/tcp -v /data:/data -l id.bind")
		res.ExpectSuccess("Cannot start bind container")

		res = vm.ContainerInspect(bindContainerName)
		res.ExpectSuccess("Container is not ready after create it")
		ip, err := res.Filter(`{[0].NetworkSettings.Networks.bridge.IPAddress}`)
		Expect(err).To(BeNil(), "Cannot retrieve network info for %q", bindContainerName)

		vm.SampleContainersActions(
			helpers.Create,
			helpers.CiliumDockerNetwork,
			fmt.Sprintf("--dns=%s", ip))

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
		By("Update resolv.conf on host to update the poller")

		// This should be disabled when DNS proxy is in place.
		vm.ExecWithSudo(`bash -c "echo -e \"nameserver 127.0.0.1\nnameserver 1.1.1.1\" > /etc/resolv.conf"`)

		// Need to restart cilium to use the latest resolv.conf info.
		vm.ExecWithSudo("systemctl restart cilium")

		areEndpointsReady = vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")

	})

	AfterAll(func() {
		// @TODO remove this one when DNS proxy is in place.
		vm.ExecWithSudo(`bash -c 'echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf'`)
		for name := range ciliumTestImages {
			vm.ContainerRm(name)
		}

		for name := range ciliumOutisdeImages {
			vm.ContainerRm(name)
		}
		vm.SampleContainersActions(helpers.Delete, "")
		vm.ContainerRm(bindContainerName)
		vm.Exec(fmt.Sprintf("docker network rm  %s", worldNetwork))
	})

	JustBeforeEach(func() {
		monitorStop = vm.MonitorStart()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		monitorStop()
	})

	AfterEach(func() {
		vm.PolicyDelAll()
	})

	AfterFailed(func() {
		GinkgoPrint(vm.Exec(
			`docker ps -q | xargs -n 1 docker inspect --format ` +
				`'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{ .Name }}'` +
				`| sed 's/ \// /'`).Output().String())
		vm.ReportFailed("cilium policy get")
	})

	expectFQDNSareApplied := func() {
		jqfilter := `jq -c '.[0].egress[]| select(.toFQDNs|length > 0) | select(.toCIDRSet|length > 0)'`
		body := func() bool {
			res := vm.Exec(fmt.Sprintf(`cilium policy get -o jsonpath='{.policy}' | %s`, jqfilter))
			return res.WasSuccessful()
		}
		err := helpers.WithTimeout(
			body,
			"ToFQDNs did not update any ToCIDRSet",
			&helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		Expect(err).To(BeNil(), "FQDN policy didn't update correctly the ToCidrSet")
	}

	fqdnPolicyImport := func(fqdnPolicy string) {
		preImportPolicyRevision, err := vm.PolicyGetRevision()
		ExpectWithOffset(1, err).To(BeNil(), "Unable to get policy revision at start of test", err)
		_, err = vm.PolicyRenderAndImport(fqdnPolicy)
		ExpectWithOffset(1, err).To(BeNil(), "Unable to import policy: %s", err)

		// The DNS poll will update the policy and regenerate. We know the initial
		// import will increment the revision by 1, and the DNS update will
		// increment it by 1 again. We can wait for two policy revisions to happen.
		// Once we have an API to expose DNS->IP mappings we can also use that to
		// ensure the lookup has completed more explicitly
		timeout_s := int64(3 * fqdn.DNSPollerInterval / time.Second) // convert to seconds
		dnsWaitBody := func() bool {
			return vm.PolicyWait(preImportPolicyRevision + 2).WasSuccessful()
		}
		err = helpers.WithTimeout(dnsWaitBody, "DNSPoller did not update IPs",
			&helpers.TimeoutConfig{Ticker: 1, Timeout: timeout_s})
		ExpectWithOffset(1, err).To(BeNil(), "Unable to update IPs")
		ExpectWithOffset(1, vm.WaitEndpointsReady()).Should(BeTrue(),
			"Endpoints are not ready after ToFQDNs DNS poll triggered a regenerate")
	}

	It("Enforces ToFQDNs policy", func() {
		By("Importing policy with ToFQDN rules")
		// notaname.cilium.io never returns IPs, and is there to test that the
		// other name does get populated.
		fqdnPolicy := `
[
  {
    "labels": [{
	  	"key": "toFQDNs-runtime-test-policy"
	  }],
    "endpointSelector": {
      "matchLabels": {
        "container:id.app1": ""
      }
    },
    "egress": [
      {
        "toPorts": [{
          "ports":[{"port": "53", "protocol": "ANY"}]
        }]
      },
      {
        "toFQDNs": [
          {
            "matchName": "world1.cilium.test"
          }
        ]
      }
    ]
  }
]`
		fqdnPolicyImport(fqdnPolicy)
		expectFQDNSareApplied()

		By("Denying egress to IPs of DNS names not in ToFQDNs, and normal IPs")
		// www.cilium.io has a different IP than cilium.io (it is CNAMEd as well!),
		// and so should be blocked.
		// cilium.io.cilium.io doesn't exist.
		// 1.1.1.1, amusingly, serves HTTP.
		for _, blockedTarget := range []string{"world2.cilium.test"} {
			res := vm.ContainerExec(helpers.App1, helpers.CurlFail(blockedTarget))
			res.ExpectFail("Curl succeeded against blocked DNS name %s" + blockedTarget)
		}

		By("Allowing egress to IPs of specified ToFQDN DNS names")
		allowedTarget := "world1.cilium.test"
		res := vm.ContainerExec(helpers.App1, helpers.CurlWithHTTPCode(allowedTarget))
		res.ExpectSuccess("Cannot access to world1.cilium.test")
	})

	It("Interaction with other ToCIDR rules", func() {
		policy := `
[
	{
		"labels": [{
			"key": "FQDN test - interaction with other toCIDRSet rules, no poller"
		}],
		"endpointSelector": {
			"matchLabels": {
				"container:id.app1": ""
			}
		},
		"egress": [
			{
				"toPorts": [{
					"ports":[{"port": "53", "protocol": "ANY"}],
					"rules": {
						"dns": [
							{"matchPattern": "*.cilium.test"}
						]
					}
				}]
			},
			{
				"toFQDNs": [{
					"matchPattern": "*.cilium.test"
				}]
			},
			{
				"toCIDRSet": [
					{"cidr": "%s/32"}
				]
			}
		]
	}
]`
		_, err := vm.PolicyRenderAndImport(fmt.Sprintf(policy, outsideIps[WorldHttpd1]))
		Expect(err).To(BeNil(), "Policy cannot be imported")

		expectFQDNSareApplied()

		By("Testing connectivity to Cilium.test domain")
		res := vm.ContainerExec(helpers.App1, helpers.CurlFail("http://world1.cilium.test"))
		res.ExpectSuccess("Cannot access to world1.cilium.test")

		By("Testing connectivity to existing CIDR rule")
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail(outsideIps[WorldHttpd1]))
		res.ExpectSuccess("Cannot access to CIDR rule when should work")

		By("Ensure connectivity to other domains is still block")
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail("http://world2.outside.test"))
		res.ExpectFail("Connectivity to outside domain successfull when it should be block")

	})

	It("Roundrobin DNS", func() {
		numberOfTries := 5
		target := "roundrobin.cilium.test"
		policy := `
[
	{
		"labels": [{
			"key": "FQDN test - interaction with other toCIDRSet rules, no poller"
		}],
		"endpointSelector": {
			"matchLabels": {
				"container:id.app1": "",
				"container:id.app2": ""
			}
		},
		"egress": [
			{
				"toPorts": [{
					"ports":[{"port": "53", "protocol": "ANY"}],
					"rules": {
						"dns": [
							{"matchPattern": "roundrobin.cilium.test"}
						]
					}
				}]
			},
			{
				"toFQDNs": [{
					"matchName": "cilium.test"
				}]
			}
		]
	}
]`
		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Policy cannot be imported")

		By("Testing %q and %q containers are allow to work with roundrobin dns", helpers.App1, helpers.App2)
		for i := 0; i < numberOfTries; i++ {
			for _, container := range []string{helpers.App1, helpers.App2} {
				By("Testing connectivity to Cilium.test domain")
				res := vm.ContainerExec(container, helpers.CurlFail(target))
				res.ExpectSuccess("Container %q cannot access to %q when should work", container, target)
			}
		}
	})

	It("Can update L7 DNS policy rules", func() {
		By("Importing policy with L7 DNS rules")
		fqdnPolicy := `
[
  {
    "labels": [{
	  	"key": "toFQDNs-runtime-test-policy"
	  }],
    "endpointSelector": {
      "matchLabels": {
        "container:id.app1": ""
      }
    },
    "egress": [
      {
        "toPorts": [{
          "ports":[{"port": "53", "protocol": "ANY"}],
					"rules": {
						"dns": [{"matchPattern": "world1.cilium.test"}]
					}
        }]
      },
      {
        "toFQDNs": [
          {
            "matchPattern": "*.cilium.test"
          }
        ]
      }
    ]
  }
]`
		_, err := vm.PolicyRenderAndImport(fqdnPolicy)
		Expect(err).To(BeNil(), "Policy cannot be imported")
		expectFQDNSareApplied()

		By("Allowing egress to IPs of only the specified DNS names")
		blockedTarget := "world2.cilium.test"
		res := vm.ContainerExec(helpers.App1, helpers.CurlFail(blockedTarget))
		res.ExpectFail("Curl succeeded against blocked DNS name " + blockedTarget)

		allowedTarget := "world1.cilium.test"
		res = vm.ContainerExec(helpers.App1, helpers.CurlWithHTTPCode(allowedTarget))
		res.ExpectSuccess("Cannot access  " + allowedTarget)

		By("Updating policy with L7 DNS rules")
		fqdnPolicy = `
[
  {
    "labels": [{
	  	"key": "toFQDNs-runtime-test-policy"
	  }],
    "endpointSelector": {
      "matchLabels": {
        "container:id.app1": ""
      }
    },
    "egress": [
      {
        "toPorts": [{
          "ports":[{"port": "53", "protocol": "ANY"}],
					"rules": {
						"dns": [{"matchPattern": "world2.cilium.test"}]
					}
        }]
      },
      {
        "toFQDNs": [
          {
            "matchPattern": "*.cilium.test"
          }
        ]
      }
    ]
  }
]`
		_, err = vm.PolicyRenderAndImport(fqdnPolicy)
		Expect(err).To(BeNil(), "Policy cannot be imported")
		expectFQDNSareApplied()

		By("Allowing egress to IPs of the new DNS name")
		allowedTarget = "world2.cilium.test"
		res = vm.ContainerExec(helpers.App1, helpers.CurlWithHTTPCode(allowedTarget))
		res.ExpectSuccess("Cannot access  " + allowedTarget)
	})
})

func getMapValues(m map[string]string) []interface{} {
	values := make([]interface{}, len(m))
	i := 0
	for _, v := range m {
		values[i] = v
		i++
	}
	return values
}

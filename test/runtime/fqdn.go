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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

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

level1CNAME.cilium.test. 1 IN CNAME world1
level2CNAME.cilium.test. 1 IN CNAME level1CNAME.cilium.test.
level3CNAME.cilium.test. 1 IN CNAME level2CNAME.cilium.test.


world1CNAME.cilium.test. 1 IN CNAME world1
world2CNAME.cilium.test. 1 IN CNAME world2
world3CNAME.cilium.test. 1 IN CNAME world3
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

var bindDNSSECTestTemplate = `
$TTL 3
$ORIGIN dnssec.test.

@       IN      SOA     dnssec.test. admin.dnssec.test. (
                        200608081       ; serial, todays date + todays serial #
                        8H              ; refresh, seconds
                        2H              ; retry, seconds
                        4W              ; expire, seconds
                        1D )            ; minimum, seconds
;
;
@               IN NS server
server.dnssec.test. IN A 127.0.0.1

world1.dnssec.test. IN A %[1]s
world2.dnssec.test. IN A %[2]s
world3.dnssec.test. IN A %[3]s
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

zone "dnssec.test" {
	type master;
	file "/etc/bind/db.dnssec.test";
	auto-dnssec maintain;
	inline-signing yes;
	key-directory "/etc/bind/keys";
};
`

var _ = Describe("RuntimeFQDNPolicies", func() {
	const (
		bindContainerName = "bind"
		worldNetwork      = "world"
		WorldHttpd1       = "WorldHttpd1"
		WorldHttpd2       = "WorldHttpd2"
		WorldHttpd3       = "WorldHttpd3"
		OutsideHttpd1     = "OutsideHttpd1"
		OutsideHttpd2     = "OutsideHttpd2"
		OutsideHttpd3     = "OutsideHttpd3"

		bindDBCilium     = "db.cilium.test"
		bindDBOutside    = "db.outside.test"
		bindDBDNSSSEC    = "db.dnssec.test"
		bindNamedConf    = "named.conf.local"
		bindNamedOptions = "named.conf.options"

		world1Target = "http://world1.cilium.test"
		world2Target = "http://world2.cilium.test"

		DNSSECDomain        = "dnssec.test"
		DNSSECWorld1Target  = "world1.dnssec.test"
		DNSSECWorld2Target  = "world2.dnssec.test"
		DNSSECContainerName = "dnssec"
	)

	var (
		vm          *helpers.SSHMeta
		monitorStop = func() error { return nil }

		ciliumTestImages = map[string]string{
			WorldHttpd1: constants.HttpdImage,
			WorldHttpd2: constants.HttpdImage,
			WorldHttpd3: constants.HttpdImage,
		}

		ciliumOutsideImages = map[string]string{
			OutsideHttpd1: constants.HttpdImage,
			OutsideHttpd2: constants.HttpdImage,
			OutsideHttpd3: constants.HttpdImage,
		}

		worldIps       = map[string]string{}
		outsideIps     = map[string]string{}
		generatedFiles = []string{bindDBCilium, bindNamedConf, bindDBOutside, bindDBDNSSSEC}
		DNSServerIP    = ""
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

		// // Installed DNSSEC domain
		bindConfig = fmt.Sprintf(bindDNSSECTestTemplate, getMapValues(worldIps)...)
		err = helpers.RenderTemplateToFile(bindDBDNSSSEC, bindConfig, os.ModePerm)
		Expect(err).To(BeNil(), "bind file can't be created")

		for name, image := range ciliumOutsideImages {
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
				filepath.Join(vm.BasePath(), file), file)).ExpectSuccess(
				"Cannot copy %q to bind container", file)
		}

		By("Setting up bind container")
		// Use a bridge network (The docker default) to be able to use this
		// server from cilium agent. This should change when DNS proxy is in
		// place.
		res := vm.ContainerCreate(
			bindContainerName,
			constants.BindContainerImage,
			"bridge",
			fmt.Sprintf("-p 53:53/udp -p 53:53/tcp -v /data:/data -l id.bind -e DNSSEC_DOMAIN=%s", DNSSECDomain))
		res.ExpectSuccess("Cannot start bind container")

		res = vm.ContainerInspect(bindContainerName)
		res.ExpectSuccess("Container is not ready after create it")
		ip, err := res.Filter(`{[0].NetworkSettings.Networks.bridge.IPAddress}`)
		DNSServerIP = ip.String()
		Expect(err).To(BeNil(), "Cannot retrieve network info for %q", bindContainerName)

		vm.SampleContainersActions(
			helpers.Create,
			helpers.CiliumDockerNetwork,
			fmt.Sprintf("--dns=%s -l app=test", DNSServerIP))

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

		for name := range ciliumOutsideImages {
			vm.ContainerRm(name)
		}
		vm.SampleContainersActions(helpers.Delete, "")
		vm.ContainerRm(bindContainerName)
		vm.Exec(fmt.Sprintf("docker network rm  %s", worldNetwork))
		vm.CloseSSHClient()
	})

	JustBeforeEach(func() {
		monitorStop = vm.MonitorStart()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		ExpectDockerContainersMatchCiliumEndpoints(vm)
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

	expectFQDNSareApplied := func(domain string, minNumIDs int) {
		escapedDomain := strings.Replace(domain, `.`, `\\.`, -1)
		jqfilter := fmt.Sprintf(`jq -c '.[] | select(.identities|length >= %d) | select(.users|length > 0) | .selector | match("^MatchName: (\\w+\\.%s|), MatchPattern: ([\\w*]+\\.%s|)$") | length > 0'`, minNumIDs, escapedDomain, escapedDomain)
		body := func() bool {
			res := vm.Exec(fmt.Sprintf(`cilium policy selectors -o json | %s`, jqfilter))
			return strings.HasPrefix(res.GetStdOut(), "true")
		}
		err := helpers.WithTimeout(
			body,
			"ToFQDNs did not update any Selectors",
			&helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		Expect(err).To(BeNil(), "FQDN policy didn't correctly update the policy selectors")
	}

	fqdnPolicyImport := func(fqdnPolicy string) {
		_, err := vm.PolicyRenderAndImport(fqdnPolicy)
		ExpectWithOffset(1, err).To(BeNil(), "Unable to import policy: %s", err)
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
		expectFQDNSareApplied("cilium.test", 1)

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
		res := vm.ContainerExec(helpers.App1, helpers.CurlWithHTTPCode(world1Target))
		res.ExpectSuccess("Cannot access to allowed DNS name %q", world1Target)
	})

	It("Validate dns-proxy monitor information", func() {

		ctx, cancel := context.WithCancel(context.Background())
		monitorCMD := vm.ExecInBackground(ctx, "cilium monitor --type=l7")
		defer cancel()

		policy := `
[
	{
		"labels": [{
			"key": "monitor"
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
							{"matchPattern": "world1.cilium.test"}
						]
					}
				}]
			},
			{
				"toFQDNs": [{
					"matchPattern": "world1.cilium.test"
				}]
			}
		]
	}
]`
		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Policy cannot be imported")

		expectFQDNSareApplied("cilium.test", 1)

		allowVerdict := "verdict Forwarded DNS Query: world1.cilium.test"
		deniedVerdict := "verdict Denied DNS Query: world2.cilium.test"

		By("Testing connectivity to Cilium.test domain")
		res := vm.ContainerExec(helpers.App1, helpers.CurlFail(world1Target))
		res.ExpectSuccess("Cannot access to %q", world1Target)

		_ = monitorCMD.WaitUntilMatch(allowVerdict)
		monitorCMD.ExpectContains(allowVerdict)
		monitorCMD.Reset()

		By("Ensure connectivity to world2 is block")
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail(world2Target))
		res.ExpectFail("Can access to %q when it should block", world1Target)
		monitorCMD.WaitUntilMatch(deniedVerdict)
		monitorCMD.ExpectContains(deniedVerdict)
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
		_, err := vm.PolicyRenderAndImport(fmt.Sprintf(policy, outsideIps[OutsideHttpd1]))
		Expect(err).To(BeNil(), "Policy cannot be imported")

		expectFQDNSareApplied("cilium.test", 1)

		By("Testing connectivity to Cilium.test domain")
		res := vm.ContainerExec(helpers.App1, helpers.CurlFail(world1Target))
		res.ExpectSuccess("Cannot access toCIDRSet allowed IP of DNS name %q", world1Target)

		By("Testing connectivity to existing CIDR rule")
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail(outsideIps[OutsideHttpd1]))
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
				"container:app": "test"
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
					"matchName": "roundrobin.cilium.test"
				}]
			}
		]
	}
]`
		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Policy cannot be imported")

		endpoints, err := vm.GetEndpointsIds()
		Expect(err).To(BeNil(), "Endpoints can't be retrieved")

		for _, container := range []string{helpers.App1, helpers.App2} {
			Expect(endpoints).To(HaveKey(container),
				"Container %q is not present in the endpoints list", container)
			ep := vm.EndpointGet(endpoints[container])
			Expect(ep).ShouldNot(BeNil(),
				"Endpoint for container %q cannot be retrieved", container)
			Expect(ep.Status.Policy.Realized.PolicyEnabled).To(
				Equal(models.EndpointPolicyEnabledEgress),
				"Endpoint %q does not have policy applied", container)
		}

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
		expectFQDNSareApplied("cilium.test", 1)

		By("Allowing egress to IPs of only the specified DNS names")
		res := vm.ContainerExec(helpers.App1, helpers.CurlFail(world2Target))
		res.ExpectFail("Curl succeeded against blocked DNS name %q", world2Target)

		res = vm.ContainerExec(helpers.App1, helpers.CurlWithHTTPCode(world1Target))
		res.ExpectSuccess("Cannot access  %q", world1Target)

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
		expectFQDNSareApplied("cilium.test", 1)

		By("Allowing egress to IPs of the new DNS name")
		res = vm.ContainerExec(helpers.App1, helpers.CurlWithHTTPCode(world2Target))
		res.ExpectSuccess("Cannot access  %q", world2Target)
	})

	It("CNAME follow", func() {

		By("Testing one level of CNAME")
		policy := `
[
	{
		"labels": [{
			"key": "CNAME follow one level"
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
					"matchName": "level1CNAME.cilium.test"
				}]
			}
		]
	}
]`

		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Policy cannot be imported")

		expectFQDNSareApplied("cilium.test", 1)
		target := "http://level1CNAME.cilium.test"
		res := vm.ContainerExec(helpers.App1, helpers.CurlFail(target))
		res.ExpectSuccess("Container %q cannot access to %q when should work", helpers.App1, target)

		By("Testing three level CNAME to same target still works")
		target = "http://level3CNAME.cilium.test"
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail(target))
		res.ExpectSuccess("Container %q cannot access to %q when should work", helpers.App1, target)

		By("Testing other CNAME in same domain should fail")
		target = "http://world2CNAME.cilium.test"
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail(target))
		res.ExpectFail("Container %q can access to %q when shouldn't work", helpers.App1, target)

		By("Testing three level of CNAME")
		policy = `
[
	{
		"labels": [{
			"key": "CNAME follow three levels"
		}],
		"endpointSelector": {
			"matchLabels": {
				"container:id.app2": ""
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
					"matchName": "level3CNAME.cilium.test"
				}]
			}
		]
	}
]`

		_, err = vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Policy cannot be imported")

		expectFQDNSareApplied("cilium.test", 1)
		target = "http://level3CNAME.cilium.test"
		res = vm.ContainerExec(helpers.App2, helpers.CurlFail(target))
		res.ExpectSuccess("Container %q cannot access to %q when should work", helpers.App2, target)
	})

	It("Enforces L3 policy even when no IPs are inserted", func() {
		By("Importing policy with toFQDNs rules")
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
        "toFQDNs": [
          {
            "matchPattern": "notadomain.cilium.io"
          }
        ]
      }
    ]
  }
]`
		_, err := vm.PolicyRenderAndImport(fqdnPolicy)
		Expect(err).To(BeNil(), "Policy cannot be imported")
		expectFQDNSareApplied("cilium.io", 0)

		By("Denying egress to any IPs or domains")
		for _, blockedTarget := range []string{"1.1.1.1", "cilium.io", "google.com"} {
			res := vm.ContainerExec(helpers.App1, helpers.CurlFail(blockedTarget))
			res.ExpectFail("Curl to %s succeeded when in deny-all due to toFQDNs" + blockedTarget)
		}
	})

	It(`Implements matchPattern: "*"`, func() {
		By(`Importing policy with matchPattern: "*" rule`)
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
						"dns": [
							{"matchPattern": "*"}
						]
					}
				}]
			},
			{
				"toFQDNs": [
				  {"matchPattern": "world1.cilium.test"},
				  {"matchPattern": "world*.cilium.test"},
				  {"matchPattern": "level*CNAME.cilium.test"}
				]
			}
    ]
  }
]`
		_, err := vm.PolicyRenderAndImport(fqdnPolicy)
		Expect(err).To(BeNil(), "Policy cannot be imported")
		expectFQDNSareApplied("cilium.test", 1)

		By("Denying egress to any IPs or domains")
		for _, allowedTarget := range []string{"world1.cilium.test", "world2.cilium.test", "world3.cilium.test", "level1CNAME.cilium.test", "level2CNAME.cilium.test"} {
			res := vm.ContainerExec(helpers.App1, helpers.CurlFail(allowedTarget))
			res.ExpectSuccess("Curl to %s failed when in deny-all due to toFQDNs", allowedTarget)
		}
		for _, blockedTarget := range []string{"1.1.1.1", "cilium.io", "google.com"} {
			res := vm.ContainerExec(helpers.App1, helpers.CurlFail(blockedTarget))
			res.ExpectFail("Curl to %s succeeded when in allow-all DNS but limited toFQDNs", blockedTarget)
		}
	})

	It("Validates DNSSEC responses", func() {
		policy := `
[
	{
		"labels": [{
			"key": "FQDN test - DNSSEC domain"
		}],
		"endpointSelector": {
			"matchLabels": {
				"container:id.dnssec": ""
			}
		},
		"egress": [
			{
				"toPorts": [{
					"ports":[{"port": "53", "protocol": "ANY"}],
					"rules": {
						"dns": [
							{"matchPattern": "world1.dnssec.test"}
						]
					}
				}]
			},
			{
				"toFQDNs": [{
					"matchPattern": "world1.dnssec.test"
				}]
			}
		]
	}
]`
		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Policy cannot be imported")

		// Selector cache is populated when a policy is applied on an endpoint.
		// DNSSEC container is not running yet, so we can't expect the FQDNs to be applied yet.
		// expectFQDNSareApplied("dnssec.test", 1)

		By("Validate that allow target is working correctly")
		res := vm.ContainerRun(
			DNSSECContainerName,
			constants.DNSSECContainerImage,
			helpers.CiliumDockerNetwork,
			fmt.Sprintf("-l id.%s --dns=%s --rm", DNSSECContainerName, DNSServerIP),
			DNSSECWorld1Target)
		res.ExpectSuccess("Cannot connect to %q when it should work", DNSSECContainerName)

		By("Validate that disallow target is working correctly")
		res = vm.ContainerRun(
			DNSSECContainerName,
			constants.DNSSECContainerImage,
			helpers.CiliumDockerNetwork,
			fmt.Sprintf("-l id.%s --dns=%s --rm", DNSSECContainerName, DNSServerIP),
			DNSSECWorld2Target)
		res.ExpectFail("Can connect to %q when it should not work", DNSSECContainerName)
	})

	Context("toFQDNs populates toCIDRSet when poller is disabled (data from proxy)", func() {
		var config = `
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
CILIUM_OPTS=--kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug --pprof=true --log-system-load --tofqdns-enable-poller=false
INITSYSTEM=SYSTEMD`
		BeforeAll(func() {
			vm.SetUpCiliumWithOptions(config)

			ExpectCiliumReady(vm)
			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
		})

		AfterAll(func() {
			vm.SetUpCilium()
			_ = vm.WaitEndpointsReady() // Don't assert because don't want to block all AfterAll.
		})

		It("Policy addition after DNS lookup", func() {
			policy := `
[
       {
               "labels": [{
                       "key": "Policy addition after DNS lookup"
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
                                                       {"matchName": "world1.cilium.test"},
                                                       {"matchPattern": "*.cilium.test"}
                                               ]
                                       }
                               }]
                       },
                       {
                               "toFQDNs": [
                                       {"matchName": "world1.cilium.test"},
                                       {"matchPattern": "*.cilium.test"}
                               ]
                       }
               ]
       }
]`

			By("Testing connectivity to %q", world1Target)
			res := vm.ContainerExec(helpers.App1, helpers.CurlFail(world1Target))
			res.ExpectSuccess("Cannot access %q", world1Target)

			By("Importing the policy")
			_, err := vm.PolicyRenderAndImport(policy)
			Expect(err).To(BeNil(), "Policy cannot be imported")

			By("Trying curl connection to %q without DNS request", world1Target)
			// The --resolve below suppresses further lookups
			curlCmd := helpers.CurlFail(fmt.Sprintf("--resolve %s:%s", world1Target, worldIps[WorldHttpd1]))
			res = vm.ContainerExec(helpers.App1, curlCmd)
			res.ExpectFail("Can access to %q when should not (No DNS request to allow the IP)", world1Target)

			By("Testing connectivity to %q", world1Target)
			res = vm.ContainerExec(helpers.App1, helpers.CurlFail(world1Target))
			res.ExpectSuccess("Cannot access to %q when it should work", world1Target)
		})
	})

	It("DNS proxy policy works if Cilium stops", func() {
		targetURL := "http://world1.cilium.test"
		targetIP := worldIps[WorldHttpd1]
		invalidURL := "http://world1.outside.test"
		invalidIP := outsideIps[OutsideHttpd1]

		policy := `
[
	{
		"labels": [{
			"key": "dns-proxy"
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
					"matchName": "world1.cilium.test"
				}]
			}
		]
	}
]`
		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Policy cannot be imported")

		expectFQDNSareApplied("cilium.test", 1)

		By("Curl from %q to %q", helpers.App1, targetURL)
		res := vm.ContainerExec(helpers.App1, helpers.CurlFail(targetURL))
		res.ExpectSuccess("Cannot connect from app1")

		By("Curl from %q to %q should fail", helpers.App1, invalidURL)
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail(invalidURL))
		res.ExpectFail("Can connect from app1 when it should not work")

		By("Stopping Cilium")

		defer func() {
			// Defer a Cilium restart to make sure that keep started when test finished.
			_ = vm.ExecWithSudo("systemctl start cilium")
			vm.WaitEndpointsReady()
		}()

		res = vm.ExecWithSudo("systemctl stop cilium")
		res.ExpectSuccess("Failed trying to stop cilium via systemctl")
		ExpectCiliumNotRunning(vm)

		By("Testing connectivity from %q to the IP %q without DNS request", helpers.App1, targetIP)
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s", targetIP))
		res.ExpectSuccess("Cannot connect to %q", targetIP)

		By("Curl from %q to %q with Cilium down", helpers.App1, targetURL)
		// When Cilium is down the DNS-proxy is also down. The Endpoint has a
		// redirect to use the DNS-proxy, so new DNS request are redirected
		// incorrectly.
		// Future Cilium versions will fix this behaviour
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail(targetURL))
		res.ExpectFail("This request should fail because no dns-proxy when cilium is stopped")

		By("Testing that invalid traffic is still block when Cilium is down", helpers.App1, invalidIP)
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s", invalidIP))
		res.ExpectFail("Can connect from app1 when it should not work")

		By("Starting Cilium again")
		Expect(vm.RestartCilium()).To(BeNil(), "Cilium cannot be started correctly")

		// Policies on docker are not persistant, so the restart connectivity is not tested at all
	})
})

// getMapValues retuns an array of interfaces with the map values.
// returned array will be sorted by map keys, the reason is that Golang does
// not support ordered maps and for DNS-config the values need to be always
// sorted.
func getMapValues(m map[string]string) []interface{} {

	values := make([]interface{}, len(m))
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		values[i] = m[k]
	}
	return values
}

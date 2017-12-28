package RuntimeTest

import (
	"fmt"
	"net"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"
)

var (
	serverImage = "httpd"
	ctCleanUpNC = "ct-clean-up-nc.py"
	ctL4Policy  = "CT-l4-policy.json"
	netcat      = "netcat"
)

type connTest struct {
	src         map[string]string
	destination map[string]string
	kind        string
	mode        string
}

func (c connTest) String() string {
	return fmt.Sprintf("%s-%s-%s", c.src["Name"], c.destination["Name"], c.kind)
}

var _ = Describe("RuntimeConntrackTable", func() {

	var initialized bool
	var logger *logrus.Entry
	var vm *helpers.SSHMeta
	var (
		HTTPPrivate   = "private"
		HTTPPublic    = "public"
		HTTPDummy     = "dummy"
		netcatPrivate = "ncPrivate"
		netcatPublic  = "ncPublic"
		server        = "server"
		server2       = "server-2"
		server3       = "server-3"
		client2       = "client-2"
		client        = "client"
	)

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(logrus.Fields{"testName": "RuntimeConntrack"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		vm.WaitUntilReady(100)
		vm.NetworkCreate(helpers.CiliumDockerNetwork, "")

		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
		res.ExpectSuccess()

		res = vm.PolicyDelAll()
		res.ExpectSuccess()

		initialized = true
	}

	containersNames := []string{server, server2, server3, client, client2, "netcat"}

	containers := func(mode string) {
		images := map[string]string{
			server:  serverImage,
			server2: serverImage,
			server3: helpers.HttpdImage,
			client2: helpers.NetperfImage,
		}

		switch mode {
		case helpers.Create:
			for k, v := range images {
				vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
			}
			cmd := fmt.Sprintf(
				"docker run -dt --name netcat --net %s -l id.server-4 busybox sleep 30000s",
				helpers.CiliumDockerNetwork)
			vm.Exec(cmd)

			cmd = fmt.Sprintf(
				"docker run -dt -v %s:/nc.py --net=%s --name client -l id.client python:2.7.14",
				vm.GetFullPath(ctCleanUpNC), helpers.CiliumDockerNetwork)
			vm.Exec(cmd)

		case helpers.Delete:
			for _, x := range containersNames {
				vm.ContainerRm(x)
			}
		}
	}

	containersMeta := func() map[string]map[string]string {
		result := map[string]map[string]string{}
		for _, x := range containersNames {
			data, err := vm.ContainerInspectNet(x)
			Expect(err).To(BeNil())
			result[x] = data
		}
		return result
	}

	countCTEntriesof := func(from, to, identityID string) (int, error) {
		// It counts the number of connection
		if govalidator.IsIPv6(to) {
			to = fmt.Sprintf(`[%s`, to)
		}

		cmd := fmt.Sprintf(`bpf ct list global | grep -F "%s -> %s" | grep "sec_id=%s" | wc -l`,
			net.JoinHostPort(from, "80"), to, identityID)
		return vm.ExecCilium(cmd).IntOutput()
	}

	testReach := func(src, dest, mode string, assertFn func() types.GomegaMatcher) {
		switch mode {
		case http:
			res := vm.ContainerExec(src, helpers.CurlFail(fmt.Sprintf(
				"http://%s/", net.JoinHostPort(dest, "80"))))
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), "Failed to curl '%s'", res.GetCmd())
		case HTTPDummy:
			cmd := fmt.Sprintf(
				"curl -s --fail -o /dev/null -w %%{http_code} --connect-timeout 5 http://%s/dummy",
				net.JoinHostPort(dest, "80"))
			res := vm.ContainerExec(src, cmd)
			valid := false
			if res.SingleOut() == "404" {
				valid = true
			}
			ExpectWithOffset(1, valid).Should(assertFn(), "Failed to curl '%s'", res.GetCmd())
		case HTTPPrivate:
			res := vm.ContainerExec(src, helpers.CurlFail(fmt.Sprintf(
				"http://%s/private", net.JoinHostPort(dest, "80"))))
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), "Failed to curl '%s'", res.GetCmd())
		case HTTPPublic:
			res := vm.ContainerExec(src, helpers.CurlFail(fmt.Sprintf(
				"http://%s/public", net.JoinHostPort(dest, "80"))))
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), "Failed to curl '%s'", res.GetCmd())
		case netcatPrivate:
			cmd := fmt.Sprintf(`bash -c "python ./nc.py 1111 5 %s 80 "/private" | head -n 1 | grep \"HTTP/1.*200 OK\""`, dest)
			res := vm.ContainerExec(src, cmd)
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), "Failed to httpRequest '%s'", res.GetCmd())
		case netcatPublic:
			cmd := fmt.Sprintf(`bash -c "python ./nc.py 1111 5 %s 80 "/public" | head -n 1 | grep \"HTTP/1.*200 OK\""`, dest)
			res := vm.ContainerExec(src, cmd)
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), "Failed to httpRequest '%s'", res.GetCmd())
		default:
			Expect(true).To(BeFalse(), "Mode %s is not defined", mode)
		}
	}

	BeforeEach(func() {
		initialize()
	})

	It("tests conntrack tables between client to server", func() {
		vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
		containers(helpers.Create)
		defer containers(helpers.Delete)
		vm.WaitEndpointsReady()

		meta := containersMeta()
		identities, err := vm.GetEndpointsIdentityIds()
		Expect(err).To(BeNil())

		_, err = vm.PolicyImport(vm.GetFullPath(ctL4Policy), 300)
		Expect(err).To(BeNil())

		testCombinations := []connTest{
			{meta[client], meta[server], helpers.IPv6, http},
			{meta[client], meta[server], helpers.IPv4, http},
			{meta[client2], meta[server], helpers.IPv6, http},
			{meta[client2], meta[server], helpers.IPv4, http},
			{meta[client], meta[server2], helpers.IPv6, http},
			{meta[client], meta[server2], helpers.IPv4, http},
			{meta[client2], meta[server2], helpers.IPv6, http},
			{meta[client2], meta[server2], helpers.IPv4, http},
		}

		for _, testCase := range testCombinations {
			testReach(testCase.src["Name"], testCase.destination[testCase.kind], testCase.mode, BeTrue)
		}

		beforeCT, err := vm.ExecCilium("bpf ct list global | wc -l").IntOutput()
		Expect(err).To(BeNil())

		beforeCTResults := map[string]int{}
		for _, testCase := range testCombinations {
			key := testCase.String()
			data, err := countCTEntriesof(
				testCase.destination[testCase.kind],
				testCase.src[testCase.kind],
				identities[testCase.src["Name"]])
			Expect(err).To(BeNil())
			Expect(data).To(Equal(2))
			beforeCTResults[key] = data
		}

		res := vm.PolicyDel("id=server-2")
		res.ExpectSuccess()

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())

		for _, testCase := range testCombinations {
			//Checking that server-2 Conntrack connections are reset to 0 correctly
			if testCase.destination["Name"] != server2 {
				continue
			}
			data, err := countCTEntriesof(
				testCase.destination[testCase.kind],
				testCase.src[testCase.kind],
				identities[testCase.src["Name"]])
			logger.WithField("Container", testCase.String()).Infof("it has '%d' connections open", data)
			Expect(err).To(BeNil())
			Expect(data).To(Equal(0))
		}

		afterCT, err := vm.ExecCilium("bpf ct list global | wc -l").IntOutput()
		Expect(err).To(BeNil())
		CTDiff := beforeCT - afterCT
		Expect(CTDiff).To(Equal(8), "CT map should have exactly 8 entries less and not %d after deleting the policy", CTDiff)

		for _, testCase := range testCombinations {
			//Test policies are still applied correctly
			assertfn := BeTrue
			if testCase.destination["Name"] == server2 {
				assertfn = BeFalse
			}
			testReach(testCase.src["Name"], testCase.destination[testCase.kind], testCase.mode, assertfn)
		}
	})

	It("test the L7 CT cleanup", func() {
		vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
		containers(helpers.Create)
		defer containers(helpers.Delete)
		vm.WaitEndpointsReady()

		meta := containersMeta()
		identities, err := vm.GetEndpointsIdentityIds()

		By("Checking Policy L4")
		Expect(err).To(BeNil())
		policyL4 := `
		[{
			"endpointSelector": {"matchLabels":{"id.server-3":""}},
			"ingress": [{
				"fromEndpoints": [{
				   "matchLabels":{"id.client":""}
				}],
				"toPorts": [{
					"ports": [{"port": "80", "protocol": "tcp"}]
				}]
			}],
			"labels": ["id=server-3"]
		}]
		`
		_, err = vm.PolicyRenderAndImport(policyL4)
		Expect(err).To(BeNil())

		testCombinations := []connTest{
			{meta[client], meta[server3], helpers.IPv6, HTTPPrivate},
			{meta[client], meta[server3], helpers.IPv4, HTTPPrivate},
			{meta[client], meta[server3], helpers.IPv6, HTTPPublic},
			{meta[client], meta[server3], helpers.IPv4, HTTPPublic},
			{meta[client], meta[server3], helpers.IPv6, netcatPrivate},
			{meta[client], meta[server3], helpers.IPv4, netcatPrivate},
			{meta[client], meta[server3], helpers.IPv6, netcatPublic},
			{meta[client], meta[server3], helpers.IPv4, netcatPublic},
		}

		for _, testCase := range testCombinations {
			testReach(testCase.src["Name"], testCase.destination[testCase.kind], testCase.mode, BeTrue)
		}

		res := vm.PolicyDel("id=server-3")
		res.WasSuccessful()

		By("Checking Policy L7")
		policyL7 := `
		[{
			"endpointSelector": {"matchLabels":{"id.server-3":""}},
			"ingress": [{
				"fromEndpoints": [{
				   "matchLabels":{"id.client":""}
				}],
				"toPorts": [{
					"ports": [{"port": "80", "protocol": "tcp"}],
					"rules": {"http": [{
						  "path": "/public",
						  "method": "GET"
					}]}
				}]
			}],
			"labels": ["id=server-3"]
		}]`
		_, err = vm.PolicyRenderAndImport(policyL7)
		Expect(err).To(BeNil())

		vm.ExecCilium("bpf ct flush global").WasSuccessful()
		CTBefore := map[string]int{}
		for _, testCase := range testCombinations {
			assertfn := BeTrue
			if strings.Contains(strings.ToLower(testCase.mode), "private") {
				assertfn = BeFalse
			}
			testReach(testCase.src["Name"], testCase.destination[testCase.kind], testCase.mode, assertfn)
			data, err := countCTEntriesof(
				testCase.destination[testCase.kind],
				testCase.src[testCase.kind],
				identities[testCase.src["Name"]])
			Expect(err).To(BeNil())
			CTBefore[testCase.String()] = data
		}

		for k, v := range CTBefore {
			Expect(v).To(Equal(6), "CTables are not correct for %s", k)
		}

		testReach(client, meta[server3][helpers.IPv4], netcatPublic, BeTrue)
		testReach(client, meta[server3][helpers.IPv6], netcatPublic, BeTrue)

		CTBefore = map[string]int{}
		for _, testCase := range testCombinations {
			data, err := countCTEntriesof(
				testCase.destination[testCase.kind],
				testCase.src[testCase.kind],
				identities[testCase.src["Name"]])
			Expect(err).To(BeNil())
			CTBefore[testCase.String()] = data
		}

		for k, v := range CTBefore {
			Expect(v).To(Equal(6), "CTables are not reuising connections for %s", k)
		}

		res = vm.PolicyDel("id=server-3")
		res.WasSuccessful()

		By("Checking Policy L7 Dummy")
		policyL7Dummy := `
		[{
			"endpointSelector": {"matchLabels":{"id.server-3":""}},
			"ingress": [{
				"fromEndpoints": [{
				   "matchLabels":{"id.client":""}
				}],
				"toPorts": [{
					"ports": [{"port": "80", "protocol": "tcp"}],
					"rules": {"http": [{
						  "path": "/dummy",
						  "method": "GET"
					}]}
				}]
			}],
			"labels": ["id=server-3"]
		}]`
		_, err = vm.PolicyRenderAndImport(policyL7Dummy)
		Expect(err).To(BeNil())
		for _, testCase := range testCombinations {
			testReach(testCase.src["Name"], testCase.destination[testCase.kind], testCase.mode, BeFalse)
		}

		testReach(client, meta[server3][helpers.IPv4], HTTPDummy, BeTrue)
		testReach(client, meta[server3][helpers.IPv6], HTTPDummy, BeTrue)
	})

	It("Check the CT cleanup on policyEnforcement default", func() {
		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
		res.ExpectSuccess()

		res = vm.PolicyDelAll()
		res.ExpectSuccess()

		containers(helpers.Create)
		defer containers(helpers.Delete)

		_, err := vm.PolicyImport(vm.GetFullPath(ctL4Policy), 300)
		Expect(err).To(BeNil())

		meta := containersMeta()
		identities, err := vm.GetEndpointsIdentityIds()
		Expect(err).To(BeNil())

		testCombinations := []connTest{
			{meta[client], meta[server], helpers.IPv6, http},
			{meta[client], meta[server], helpers.IPv4, http},
			{meta[client2], meta[server], helpers.IPv6, http},
			{meta[client2], meta[server], helpers.IPv4, http},
		}

		for _, testCase := range testCombinations {
			testReach(testCase.src["Name"], testCase.destination[testCase.kind], testCase.mode, BeTrue)

			data, err := countCTEntriesof(
				testCase.destination[testCase.kind],
				testCase.src[testCase.kind],
				identities[testCase.src["Name"]])
			Expect(err).To(BeNil())
			Expect(data).To(Equal(2))
		}
		beforeCT, err := vm.ExecCilium("bpf ct list global | wc -l").IntOutput()
		Expect(err).To(BeNil())

		res = vm.PolicyDel("id=server")
		res.ExpectSuccess()

		for _, testCase := range testCombinations {
			data, err := countCTEntriesof(
				testCase.destination[testCase.kind],
				testCase.src[testCase.kind],
				identities[testCase.src["Name"]])
			Expect(err).To(BeNil())
			Expect(data).To(Equal(0))
		}

		afterCT, err := vm.ExecCilium("bpf ct list global | wc -l").IntOutput()
		Expect(err).To(BeNil())
		CTDiff := beforeCT - afterCT
		Expect(CTDiff).To(Equal(8), "CT map should have exactly 8 entries less and not %d after deleting the policy", CTDiff)
	})
})

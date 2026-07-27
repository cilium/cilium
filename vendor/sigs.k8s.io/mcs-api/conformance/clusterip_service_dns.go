/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package conformance

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/mcs-api/pkg/apis/v1beta1"
)

var _ = Describe("", Label(OptionalLabel, DNSLabel, ClusterIPLabel), func() {
	t := newTestDriver()

	Specify("A DNS lookup of the <service>.<ns>.svc."+dnsDomain+" domain for a ClusterIP service should resolve to the "+
		"clusterset IP", func(ctx context.Context) {
		AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

		for _, client := range clients {
			serviceImport := t.awaitServiceImport(ctx, &client, t.helloService.Name, false,
				func(g Gomega, serviceImport *v1beta1.ServiceImport) {
					g.Expect(serviceImport.Spec.IPs).ToNot(BeEmpty(), "ServiceImport on cluster %q does not contain an IP", client.name)
				})

			By(fmt.Sprintf("Found ServiceImport on cluster %q with clusterset IPs %v",
				client.name, strings.Join(serviceImport.Spec.IPs, ",")))

			for _, clusterSetIP := range serviceImport.Spec.IPs {
				command := []string{"sh", "-c", fmt.Sprintf("nslookup -type=%s %s.%s.svc.%s.",
					dnsRecordTypeOf(ipFamilyOf(clusterSetIP)), t.helloService.Name, t.namespace, dnsDomain)}

				By(fmt.Sprintf("Executing %s command %q on cluster %q", ipFamilyOf(clusterSetIP),
					strings.Join(command, " "), client.name))

				t.awaitCmdOutputMatches(&client, command, clusterSetIP, 1, reportNonConformant(""))
			}
		}
	})

	Specify("A DNS SRV query of the <service>.<ns>.svc."+dnsDomain+" domain for a ClusterIP service should return valid SRV "+
		"records", func() {
		AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

		domainName := fmt.Sprintf("%s.%s.svc.%s", t.helloService.Name, t.namespace, dnsDomain)

		for _, client := range clients {
			expSRVRecs := []srvRecord{{
				port:       t.helloService.Spec.Ports[0].Port,
				domainName: domainName,
			}}

			srvRecs := t.expectSRVRecords(&client, domainName, len(expSRVRecs))

			Expect(srvRecs).To(Equal(expSRVRecs), reportNonConformant(
				fmt.Sprintf("Received SRV records %v do not match the expected records %v", srvRecs, expSRVRecs)))
		}
	})

	Specify("DNS lookups of the <service>.<ns>.svc.cluster.local domain for a ClusterIP service should only resolve "+
		"local services", func(ctx context.Context) {
		AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

		By(fmt.Sprintf("Retrieving local Service on cluster %q", clients[0].name))

		var resolvedIP string

		Eventually(func(ctx context.Context) string {
			svc, err := clients[0].k8s.CoreV1().Services(t.namespace).Get(ctx, t.helloService.Name, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred(), "Error retrieving the local Service")

			resolvedIP = svc.Spec.ClusterIP

			return resolvedIP
		}).WithContext(ctx).Within(20*time.Second).ProbeEvery(1*time.Second).ShouldNot(BeEmpty(), "The service was not assigned a cluster IP")

		By(fmt.Sprintf("Found local Service cluster IP %q", resolvedIP))

		// Add trailing dot to prevent search domain from being appended
		command := []string{"sh", "-c", fmt.Sprintf("nslookup -type=%s %s.%s.svc.cluster.local.",
			dnsRecordTypeOf(ipFamilyOf(resolvedIP)), t.helloService.Name, t.namespace)}

		By(fmt.Sprintf("Executing command %q on cluster %q", strings.Join(command, " "), clients[0].name))

		t.awaitCmdOutputMatches(&clients[0], command, resolvedIP, 1, reportNonConformant(""))
	})
})

func (t *testDriver) expectSRVRecords(c *clusterClients, domainName string, expectedCount int) []srvRecord {
	// Add trailing dot to prevent search domain from being appended
	command := []string{"sh", "-c", "nslookup -type=SRV " + domainName + "."}

	By(fmt.Sprintf("Executing command %q on cluster %q", strings.Join(command, " "), c.name))

	var srvRecs []srvRecord

	Eventually(func(g Gomega) {
		srvRecs = parseSRVRecords(t.execCmdOnRequestPod(c, command))
		g.Expect(srvRecs).To(HaveLen(expectedCount),
			fmt.Sprintf("Expected %d SRV records but got %d: %v", expectedCount, len(srvRecs), srvRecs))
	}, 20, 1).Should(Succeed(), reportNonConformant(""))

	return srvRecs
}

// Match SRV records from nslookup of the form:
//
//	hello.mcs-conformance-1686874467.svc.clusterset.local	service = 0 50 42 hello.mcs-conformance-1686874467.svc.clusterset.local
//
// to extract the port and target domain name (the last two tokens)
var srvRecordRegEx = regexp.MustCompile(`.*=\s*\d*\s*\d*\s*(\d*)\s*([a-zA-Z0-9-.]*)`)

type srvRecord struct {
	port       int32
	domainName string
}

func (s srvRecord) String() string {
	return fmt.Sprintf("port:%d, domainName:%q", s.port, s.domainName)
}

func parseSRVRecords(str string) []srvRecord {
	var recs []srvRecord

	matches := srvRecordRegEx.FindAllStringSubmatch(str, -1)
	for i := range matches {
		// First match at index 0 is the full text that was matched; index 1 is the port and index 2 is the domain name.
		port, _ := strconv.ParseInt(matches[i][1], 10, 32)
		domainName := matches[i][2]
		// Strip trailing period from FQDN (some nslookup versions include it)
		domainName = strings.TrimSuffix(domainName, ".")
		recs = append(recs, srvRecord{
			port:       int32(port),
			domainName: domainName,
		})
	}

	return recs
}

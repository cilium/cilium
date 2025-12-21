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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

var _ = Describe("", Label(OptionalLabel, DNSLabel, ClusterIPLabel), func() {
	t := newTestDriver()

	Specify("A DNS lookup of the <service>.<ns>.svc.clusterset.local domain for a ClusterIP service should resolve to the "+
		"clusterset IP", func() {
		AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

		By("Retrieving ServiceImport")

		serviceImports := []*v1alpha1.ServiceImport{}
		for _, client := range clients {
			serviceImport := t.awaitServiceImport(&client, t.helloService.Name, false,
				func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
					g.Expect(serviceImport.Spec.IPs).ToNot(BeEmpty(), "ServiceImport on cluster %q does not contain an IP", client.name)
				})
			serviceImports = append(serviceImports, serviceImport)
		}

		command := []string{"sh", "-c", fmt.Sprintf("nslookup %s.%s.svc.clusterset.local", t.helloService.Name, t.namespace)}
		for i, client := range clients {
			clusterSetIP := serviceImports[i].Spec.IPs[0]
			By(fmt.Sprintf("Found ServiceImport on cluster %q with clusterset IP %q", client.name, clusterSetIP))
			By(fmt.Sprintf("Executing command %q on cluster %q", strings.Join(command, " "), client.name))

			t.awaitCmdOutputMatches(&client, command, clusterSetIP, 1, reportNonConformant(""))
		}
	})

	Specify("A DNS SRV query of the <service>.<ns>.svc.clusterset.local domain for a ClusterIP service should return valid SRV "+
		"records", func() {
		AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

		domainName := fmt.Sprintf("%s.%s.svc.clusterset.local", t.helloService.Name, t.namespace)

		for _, client := range clients {
			srvRecs := t.expectSRVRecords(&client, domainName)

			expSRVRecs := []srvRecord{{
				port:       t.helloService.Spec.Ports[0].Port,
				domainName: domainName,
			}}

			Expect(srvRecs).To(Equal(expSRVRecs), reportNonConformant(
				fmt.Sprintf("Received SRV records %v do not match the expected records %v", srvRecs, expSRVRecs)))
		}
	})

	Specify("DNS lookups of the <service>.<ns>.svc.cluster.local domain for a ClusterIP service should only resolve "+
		"local services", func() {
		AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

		By(fmt.Sprintf("Retrieving local Service on cluster %q", clients[0].name))

		var resolvedIP string

		Eventually(func() string {
			svc, err := clients[0].k8s.CoreV1().Services(t.namespace).Get(context.TODO(), t.helloService.Name, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred(), "Error retrieving the local Service")

			resolvedIP = svc.Spec.ClusterIP

			return resolvedIP
		}, 20, 1).ShouldNot(BeEmpty(), "The service was not assigned a cluster IP")

		By(fmt.Sprintf("Found local Service cluster IP %q", resolvedIP))

		command := []string{"sh", "-c", fmt.Sprintf("nslookup %s.%s.svc.cluster.local", t.helloService.Name, t.namespace)}

		By(fmt.Sprintf("Executing command %q on cluster %q", strings.Join(command, " "), clients[0].name))

		t.awaitCmdOutputMatches(&clients[0], command, resolvedIP, 1, reportNonConformant(""))
	})
})

func (t *testDriver) expectSRVRecords(c *clusterClients, domainName string) []srvRecord {
	command := []string{"sh", "-c", "nslookup -type=SRV " + domainName}

	By(fmt.Sprintf("Executing command %q on cluster %q", strings.Join(command, " "), c.name))

	var srvRecs []srvRecord

	Eventually(func() []srvRecord {
		srvRecs = parseSRVRecords(t.execCmdOnRequestPod(c, command))
		return srvRecs
	}, 20, 1).ShouldNot(BeEmpty(), reportNonConformant(""))

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
		recs = append(recs, srvRecord{
			port:       int32(port),
			domainName: matches[i][2],
		})
	}

	return recs
}

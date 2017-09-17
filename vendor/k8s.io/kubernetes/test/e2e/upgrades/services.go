/*
Copyright 2017 The Kubernetes Authors.

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

package upgrades

import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
)

// ServiceUpgradeTest tests that a service is available before and
// after a cluster upgrade. During a master-only upgrade, it will test
// that a service remains available during the upgrade.
type ServiceUpgradeTest struct {
	jig          *framework.ServiceTestJig
	tcpService   *v1.Service
	tcpIngressIP string
	svcPort      int
}

func (ServiceUpgradeTest) Name() string { return "service-upgrade" }

func shouldTestPDBs() bool { return framework.ProviderIs("gce", "gke") }

// Setup creates a service with a load balancer and makes sure it's reachable.
func (t *ServiceUpgradeTest) Setup(f *framework.Framework) {
	serviceName := "service-test"
	jig := framework.NewServiceTestJig(f.ClientSet, serviceName)

	ns := f.Namespace

	By("creating a TCP service " + serviceName + " with type=LoadBalancer in namespace " + ns.Name)
	tcpService := jig.CreateTCPServiceOrFail(ns.Name, func(s *v1.Service) {
		s.Spec.Type = v1.ServiceTypeLoadBalancer
	})
	tcpService = jig.WaitForLoadBalancerOrFail(ns.Name, tcpService.Name, framework.LoadBalancerCreateTimeoutDefault)
	jig.SanityCheckService(tcpService, v1.ServiceTypeLoadBalancer)

	// Get info to hit it with
	tcpIngressIP := framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0])
	svcPort := int(tcpService.Spec.Ports[0].Port)

	By("creating pod to be part of service " + serviceName)
	rc := jig.RunOrFail(ns.Name, jig.AddRCAntiAffinity)

	if shouldTestPDBs() {
		By("creating a PodDisruptionBudget to cover the ReplicationController")
		jig.CreatePDBOrFail(ns.Name, rc)
	}

	// Hit it once before considering ourselves ready
	By("hitting the pod through the service's LoadBalancer")
	jig.TestReachableHTTP(tcpIngressIP, svcPort, framework.LoadBalancerLagTimeoutDefault)

	t.jig = jig
	t.tcpService = tcpService
	t.tcpIngressIP = tcpIngressIP
	t.svcPort = svcPort
}

// Test runs a connectivity check to the service.
func (t *ServiceUpgradeTest) Test(f *framework.Framework, done <-chan struct{}, upgrade UpgradeType) {
	switch upgrade {
	case MasterUpgrade:
		t.test(f, done, true)
	case NodeUpgrade:
		// Node upgrades should test during disruption only on GCE/GKE for now.
		t.test(f, done, shouldTestPDBs())
	default:
		t.test(f, done, false)
	}
}

// Teardown cleans up any remaining resources.
func (t *ServiceUpgradeTest) Teardown(f *framework.Framework) {
	// rely on the namespace deletion to clean up everything
}

func (t *ServiceUpgradeTest) test(f *framework.Framework, done <-chan struct{}, testDuringDisruption bool) {
	if testDuringDisruption {
		// Continuous validation
		By("continuously hitting the pod through the service's LoadBalancer")
		wait.Until(func() {
			t.jig.TestReachableHTTP(t.tcpIngressIP, t.svcPort, framework.LoadBalancerLagTimeoutDefault)
		}, framework.Poll, done)
	} else {
		// Block until upgrade is done
		By("waiting for upgrade to finish without checking if service remains up")
		<-done
	}

	// Sanity check and hit it once more
	By("hitting the pod through the service's LoadBalancer")
	t.jig.TestReachableHTTP(t.tcpIngressIP, t.svcPort, framework.LoadBalancerLagTimeoutDefault)
	t.jig.SanityCheckService(t.tcpService, v1.ServiceTypeLoadBalancer)
}

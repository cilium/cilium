// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bnechmark

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/cilium/cilium/pkg/cidr"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

var (
	initialObjects = []k8sRuntime.Object{
		&corev1.Node{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Node",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   "worker",
				Labels: map[string]string{"kubernetes.io/hostname": "worker"},
			},
			Spec: corev1.NodeSpec{
				PodCIDR:  cidr.MustParseCIDR("10.244.1.0/24").String(),
				PodCIDRs: []string{cidr.MustParseCIDR("10.244.1.0/24").String()},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{},
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "172.18.0.2"},
					{Type: corev1.NodeHostName, Address: "worker"},
				},
			},
		},
	}
)

func newService(ns, n string, clusterIP string, nodePort int32) *slim_corev1.Service {
	policy := slim_corev1.IPFamilyPolicySingleStack
	return &slim_corev1.Service{
		TypeMeta:   slim_metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: slim_metav1.ObjectMeta{Name: n, Namespace: ns, UID: k8sTypes.UID(n)},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP:      clusterIP,
			ClusterIPs:     []string{clusterIP},
			Type:           slim_corev1.ServiceTypeNodePort,
			IPFamilyPolicy: &policy,
			IPFamilies:     []slim_corev1.IPFamily{slim_corev1.IPv4Protocol},
			Ports:          []slim_corev1.ServicePort{{Name: "http", NodePort: nodePort, Protocol: slim_corev1.ProtocolTCP, Port: 80}},
		},
		Status: slim_corev1.ServiceStatus{},
	}
}

func newEndpointSlice(ns, n, service string, backendIP string) *slim_discoveryv1.EndpointSlice {
	portName := "http"
	proto := slim_corev1.ProtocolTCP
	port := int32(80)
	nodeName := "worker"
	yep := true
	nope := false
	return &slim_discoveryv1.EndpointSlice{
		TypeMeta: slim_metav1.TypeMeta{APIVersion: "discovery.k8s.io/v1", Kind: "EndpointSlice"},
		ObjectMeta: slim_metav1.ObjectMeta{Name: n, Namespace: ns, UID: k8sTypes.UID(n), Labels: map[string]string{
			"kubernetes.io/service-name": service,
		}},
		AddressType: slim_discoveryv1.AddressTypeIPv4,
		Endpoints: []slim_discoveryv1.Endpoint{
			{
				Addresses: []string{backendIP},
				Conditions: slim_discoveryv1.EndpointConditions{
					Ready:       &yep,
					Serving:     &yep,
					Terminating: &nope,
				},
				NodeName: &nodeName,
			},
		},
		Ports: []slim_discoveryv1.EndpointPort{
			{
				Name:     &portName,
				Protocol: &proto,
				Port:     &port,
			},
		},
	}
}

const numServicesAndBackends = 10000

func validate(test *suite.ControlPlaneTest, start time.Time) error {
	lbmap := test.Datapath.LBMockMap()

	// Surrogate, ClusterIP and NodePort
	expectedServices := 3 * numServicesAndBackends

	if len(lbmap.ServiceByID) == expectedServices && len(lbmap.BackendByID) == numServicesAndBackends {
		delta := time.Since(start)
		fmt.Printf(">>> Done in %s\n", delta)
		return nil
	}
	fmt.Printf(">>> Not done yet: %d\n", len(lbmap.ServiceByID))
	return fmt.Errorf("unexpected counts: %d, %d", len(lbmap.ServiceByID), len(lbmap.BackendByID))
	/*
		cnp, err := getDummyCNP(test)
		if err != nil {
			return err
		}
		if len(cnp.Status.Nodes) != len(dummyCNP.Status.Nodes) {
			return fmt.Errorf("number of updates in CNP Status Nodes should be: %d, found: %d", len(dummyCNP.Status.Nodes), len(cnp.Status.Nodes))
		}

		ccnp, err := getDummyCCNP(test)
		if err != nil {
			return err
		}
		if len(ccnp.Status.Nodes) != len(dummyCCNP.Status.Nodes) {
			return fmt.Errorf("number of updates in CCNP Status Nodes should be: %d, found: %d", len(dummyCCNP.Status.Nodes), len(ccnp.Status.Nodes))
		}*/
}

func createObjects(test *suite.ControlPlaneTest) error {

	tracker := test.SlimTracker()

	clusterIP := make([]byte, 4)
	backendIP := make([]byte, 4)

	for i := 0; i < numServicesAndBackends; i++ {
		svc := fmt.Sprintf("svc%d", i)
		eps := fmt.Sprintf("eps%d", i)
		binary.BigEndian.PutUint32(clusterIP, 0x01000000+uint32(i+1))
		binary.BigEndian.PutUint32(backendIP, 0x01000000+uint32(i+1))

		tracker.Add(
			newService("test", svc, net.IP(clusterIP).String(), int32(30000+i)),
		)
		tracker.Add(
			newEndpointSlice("test", eps, svc, net.IP(backendIP).String()),
		)
	}
	return nil
}

func init() {

	watch.DefaultChanSize = numServicesAndBackends

	suite.AddTestCase("Benchmark", func(t *testing.T) {
		k8sVersions := controlplane.K8sVersions()
		start := time.Now()
		// We only need to test the last k8s version
		test := suite.NewControlPlaneTest(t, "worker", k8sVersions[len(k8sVersions)-1])

		//logging.SetLogLevelToDebug()

		// When running with GC disabled, the Nodes Status updates should not be deleted.
		test.
			UpdateObjects(initialObjects...).
			SetupEnvironment().
			StartAgent(func(_ *option.DaemonConfig) {}).
			Execute(func() error { return createObjects(test) }).
			Eventually(func() error { return validate(test, start) }).
			StopAgent().
			ClearEnvironment()

	})
}

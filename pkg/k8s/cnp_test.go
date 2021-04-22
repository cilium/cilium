// Copyright 2019-2021 Authors of Cilium
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

// +build !privileged_tests

package k8s_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	go_runtime "runtime"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/defaults"
	. "github.com/cilium/cilium/pkg/k8s"
	ciliumClient "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	informer "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	k8sconfig "github.com/cilium/cilium/pkg/k8s/config"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

// logging field definitions
const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)

type K8sIntegrationSuite struct{}

var _ = Suite(&K8sIntegrationSuite{})

func (k *K8sIntegrationSuite) SetUpSuite(c *C) {
	if true {
		logging.DefaultLogger.SetLevel(logrus.PanicLevel)
		log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
	}
	if os.Getenv("INTEGRATION") != "" {
		if k8sConfigPath := os.Getenv("KUBECONFIG"); k8sConfigPath == "" {
			Configure("", "/var/lib/cilium/cilium.kubeconfig", defaults.K8sClientQPSLimit, defaults.K8sClientBurst)
		} else {
			Configure("", k8sConfigPath, defaults.K8sClientQPSLimit, defaults.K8sClientBurst)
		}
		restConfig, err := CreateConfig()
		c.Assert(err, IsNil)
		apiextensionsclientset, err := apiextensionsclient.NewForConfig(restConfig)
		c.Assert(err, IsNil)
		err = ciliumClient.CreateCustomResourceDefinitions(apiextensionsclientset)
		c.Assert(err, IsNil)

		client, err := clientset.NewForConfig(restConfig)
		c.Assert(err, IsNil)
		client.CiliumV2().CiliumNetworkPolicies("default").Delete(context.TODO(), "testing-policy", metav1.DeleteOptions{})
	}
}

func testUpdateCNPNodeStatusK8s(integrationTest bool, k8sVersion string, c *C) {
	// For k8s <v1.13
	// the unit tests will perform 3 actions, A, B and C where:
	// A-1.10) update k8s1 node status
	//    this will make 1 attempt as it is the first node populating status
	// B-1.10) update k8s2 node status
	//    this will make 3 attempts
	// C-1.10) update k8s1 node status with revision=2 and enforcing=false
	//    this will make 3 attempts
	// the code paths for A-1.10, B-1.10 and C-1.10 can be found in the comments

	// For k8s >=v1.13
	// the unit tests will perform 3 actions, A, B and C where:
	// A-1.13) update k8s1 node status
	//         this will make 1 attempt as it is the first node populating status
	// B-1.13) update k8s2 node status
	//         this will make 2 attempts
	// C-1.13) update k8s1 node status with revision=2 and enforcing=false
	//         this will make 2 attempts
	// the code paths for A-1.13, B-1.13 and C-1.13 can be found in the comments

	err := k8sversion.Force(k8sVersion)
	c.Assert(err, IsNil)

	cnp := &types.SlimCNP{
		CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "CiliumNetworkPolicy",
				APIVersion: "cilium.io/v2",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testing-policy",
				Namespace: "default",
			},
			Spec: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
						},
					},
				},
			},
		},
	}

	wantedCNP := cnp.DeepCopy()

	wantedCNPS := v2.CiliumNetworkPolicyStatus{
		Nodes: map[string]v2.CiliumNetworkPolicyNodeStatus{
			"k8s1": {
				Enforcing:   true,
				Revision:    1,
				OK:          true,
				LastUpdated: slim_metav1.Time{},
				Annotations: map[string]string{
					"foo":                            "bar",
					"i-will-disappear-in-2nd-update": "bar",
				},
			},
			"k8s2": {
				Enforcing:   true,
				Revision:    2,
				OK:          true,
				LastUpdated: slim_metav1.Time{},
			},
		},
	}

	wantedCNP.Status = wantedCNPS

	var ciliumNPClient clientset.Interface
	if integrationTest {
		restConfig, err := CreateConfig()
		c.Assert(err, IsNil)
		ciliumNPClient, err = clientset.NewForConfig(restConfig)
		c.Assert(err, IsNil)
		cnp.CiliumNetworkPolicy, err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Create(context.TODO(), cnp.CiliumNetworkPolicy, metav1.CreateOptions{})
		c.Assert(err, IsNil)
		defer func() {
			err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Delete(context.TODO(), cnp.GetName(), metav1.DeleteOptions{})
			c.Assert(err, IsNil)
		}()
	} else {
		ciliumNPClientFake := &fake.Clientset{}
		ciliumNPClientFake.AddReactor("patch", "ciliumnetworkpolicies",
			func(action k8sTesting.Action) (bool, runtime.Object, error) {
				pa := action.(k8sTesting.PatchAction)
				time.Sleep(1 * time.Millisecond)
				var receivedJsonPatch []JSONPatch
				err := json.Unmarshal(pa.GetPatch(), &receivedJsonPatch)
				c.Assert(err, IsNil)

				switch {
				case receivedJsonPatch[0].OP == "test" && receivedJsonPatch[0].Path == "/status":
					switch {
					case receivedJsonPatch[0].Value == nil:
						cnpns := receivedJsonPatch[1].Value.(map[string]interface{})
						nodes := cnpns["nodes"].(map[string]interface{})
						if nodes["k8s1"] == nil {
							// codepath B-1.10) and B-1.13) 1st attempt
							// This is an attempt from k8s2 so we need
							// to return an error because `/status` is not nil as
							// it was previously set by k8s1
							return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonInvalid}}
						}
						// codepath A-1.10), C-1.10), A-1.13) and C-1.13)
						n := nodes["k8s1"].(map[string]interface{})

						if n["localPolicyRevision"].(float64) == 2 {
							// codepath C-1.10) and C-1.13) 1st attempt
							// This is an attempt from k8s1 to update its status
							// again, return an error because `/status` is not nil
							// as it was previously set by k8s1
							return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonInvalid}}
						}

						// codepath A-1.10) and A-1.13)

						// Ignore lastUpdated timestamp as it will mess up with
						// the deepequals
						n["lastUpdated"] = nil

						// Remove k8s2 from the nodes status.
						cnpsK8s1 := wantedCNPS.DeepCopy()
						delete(cnpsK8s1.Nodes, "k8s2")
						createStatusAndNodePatch := []JSONPatch{
							{
								OP:    "test",
								Path:  "/status",
								Value: nil,
							},
							{
								OP:    "add",
								Path:  "/status",
								Value: cnpsK8s1,
							},
						}
						expectedJSONPatchBytes, err := json.Marshal(createStatusAndNodePatch)
						c.Assert(err, IsNil)
						var expectedJSONPatch []JSONPatch
						err = json.Unmarshal(expectedJSONPatchBytes, &expectedJSONPatch)
						c.Assert(err, IsNil)

						c.Assert(receivedJsonPatch, checker.DeepEquals, expectedJSONPatch)

						// Copy the status the the cnp so we can compare it at
						// the end of this test to make sure everything is alright.
						cnp.Status = *cnpsK8s1
						return true, cnp.CiliumNetworkPolicy, nil

					case receivedJsonPatch[0].Value != nil:
						// codepath B-1.10) and C-1.10) 2nd attempt
						// k8s1 and k8s2 knows that `/status` exists and was created
						// by a different node so he just needs to add itself to
						// the list of nodes.
						// "Unfortunately" the list of node is not-empty so
						// the test value of `/status` needs to fail
						c.Assert(cnp.Status.Nodes, Not(Equals), 0)
						return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonInvalid}}
					}
				case receivedJsonPatch[0].OP == "replace":
					// codepath B-1.13) and C-1.13) 2nd attempt
					fallthrough
				case receivedJsonPatch[0].OP == "add":
					cnpns := receivedJsonPatch[0].Value.(map[string]interface{})
					// codepath B-1.10) and C-1.10) 3rd attempt
					// k8s2 knows that `/status` exists and was created
					// by a different node so he just needs to add itself to
					// the list of nodes.
					if len(cnp.Status.Nodes) == 1 {
						// codepath B-1.10) 3rd attempt
						// k8s1 knows that `/status` exists and was populated
						// by a different node so he just needs to add (update)
						// itself to the list of nodes.

						// Ignore lastUpdated timestamp as it will mess up with
						// the deepequals
						cnpns["lastUpdated"] = nil

						// Remove k8s1 from the nodes status.
						cnpsK8s2 := wantedCNPS.DeepCopy()
						delete(cnpsK8s2.Nodes, "k8s1")

						createStatusAndNodePatch := []JSONPatch{
							{
								OP:    receivedJsonPatch[0].OP,
								Path:  "/status/nodes/k8s2",
								Value: cnpsK8s2.Nodes["k8s2"],
							},
						}
						expectedJSONPatchBytes, err := json.Marshal(createStatusAndNodePatch)
						c.Assert(err, IsNil)
						var expectedJSONPatch []JSONPatch
						err = json.Unmarshal(expectedJSONPatchBytes, &expectedJSONPatch)
						c.Assert(err, IsNil)

						c.Assert(receivedJsonPatch, checker.DeepEquals, expectedJSONPatch)

						cnp.Status.Nodes["k8s2"] = cnpsK8s2.Nodes["k8s2"]
						return true, cnp.CiliumNetworkPolicy, nil
					}

					// codepath C-1.10) 3rd attempt

					// Ignore lastUpdated timestamp as it will mess up with
					// the deepequals
					cnpns["lastUpdated"] = nil

					// Remove k8s2 from the nodes status.
					cnpsK8s1 := wantedCNPS.DeepCopy()
					delete(cnpsK8s1.Nodes, "k8s2")
					// This update from k8s1 should have enforcing=false and
					// revision=2
					nWanted := cnpsK8s1.Nodes["k8s1"]
					nWanted.Revision = 2
					nWanted.Enforcing = false
					cnpsK8s1.Nodes["k8s1"] = nWanted

					createStatusAndNodePatch := []JSONPatch{
						{
							OP:    receivedJsonPatch[0].OP,
							Path:  "/status/nodes/k8s1",
							Value: nWanted,
						},
					}
					expectedJSONPatchBytes, err := json.Marshal(createStatusAndNodePatch)
					c.Assert(err, IsNil)
					var expectedJSONPatch []JSONPatch
					err = json.Unmarshal(expectedJSONPatchBytes, &expectedJSONPatch)
					c.Assert(err, IsNil)

					c.Assert(receivedJsonPatch, checker.DeepEquals, expectedJSONPatch)

					cnp.Status.Nodes["k8s1"] = cnpsK8s1.Nodes["k8s1"]
					return true, cnp.CiliumNetworkPolicy, nil
				}
				// should never reach this point
				c.FailNow()
				return true, nil, fmt.Errorf("should not been called")
			})
		ciliumNPClient = ciliumNPClientFake
	}

	updateContext := &CNPStatusUpdateContext{
		CiliumNPClient: ciliumNPClient,
		NodeName:       "k8s1",
	}

	cnpns := wantedCNPS.Nodes["k8s1"]
	err = updateContext.UpdateViaAPIServer(cnp, cnpns.Enforcing, cnpns.OK, err, cnpns.Revision, cnpns.Annotations)
	c.Assert(err, IsNil)

	if integrationTest {
		cnp.CiliumNetworkPolicy, err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Get(context.TODO(), cnp.GetName(), metav1.GetOptions{})
		c.Assert(err, IsNil)
	}

	updateContext = &CNPStatusUpdateContext{
		CiliumNPClient: ciliumNPClient,
		NodeName:       "k8s2",
	}

	cnpns = wantedCNPS.Nodes["k8s2"]
	err = updateContext.UpdateViaAPIServer(cnp, cnpns.Enforcing, cnpns.OK, err, cnpns.Revision, cnpns.Annotations)
	c.Assert(err, IsNil)

	if integrationTest {
		cnp.CiliumNetworkPolicy, err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Get(context.TODO(), cnp.GetName(), metav1.GetOptions{})
		c.Assert(err, IsNil)

		// Ignore timestamps
		n := cnp.Status.Nodes["k8s1"]
		n.LastUpdated = slim_metav1.Time{}
		cnp.Status.Nodes["k8s1"] = n
		n = cnp.Status.Nodes["k8s2"]
		n.LastUpdated = slim_metav1.Time{}
		cnp.Status.Nodes["k8s2"] = n

		c.Assert(cnp.Status, checker.DeepEquals, wantedCNP.Status)
	} else {
		c.Assert(cnp.Status, checker.DeepEquals, wantedCNP.Status)
	}

	n := wantedCNP.Status.Nodes["k8s1"]
	n.Revision = 2
	n.Enforcing = false
	n.Annotations = map[string]string{
		"foo": "bar",
	}
	wantedCNP.Status.Nodes["k8s1"] = n

	updateContext = &CNPStatusUpdateContext{
		CiliumNPClient: ciliumNPClient,
		NodeName:       "k8s1",
	}

	cnpns = wantedCNPS.Nodes["k8s1"]
	err = updateContext.UpdateViaAPIServer(cnp, cnpns.Enforcing, cnpns.OK, err, cnpns.Revision, cnpns.Annotations)
	c.Assert(err, IsNil)

	if integrationTest {
		cnp.CiliumNetworkPolicy, err = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Get(context.TODO(), cnp.GetName(), metav1.GetOptions{})
		c.Assert(err, IsNil)

		// Ignore timestamps
		n := cnp.Status.Nodes["k8s1"]
		n.LastUpdated = slim_metav1.Time{}
		cnp.Status.Nodes["k8s1"] = n
		n = cnp.Status.Nodes["k8s2"]
		n.LastUpdated = slim_metav1.Time{}
		cnp.Status.Nodes["k8s2"] = n

		c.Assert(cnp.Status, checker.DeepEquals, wantedCNP.Status)
	} else {
		c.Assert(cnp.Status, checker.DeepEquals, wantedCNP.Status)
	}
}

func (k *K8sIntegrationSuite) Test_updateCNPNodeStatus_1_10(c *C) {
	c.Skip("Test not available as implementation is not made")
	testUpdateCNPNodeStatusK8s(os.Getenv("INTEGRATION") != "", "1.10", c)
}

func (k *K8sIntegrationSuite) Test_updateCNPNodeStatus_1_13(c *C) {
	testUpdateCNPNodeStatusK8s(os.Getenv("INTEGRATION") != "", "1.13", c)
}

func benchmarkCNPNodeStatusController(integrationTest bool, nNodes int, nParallelClients int, k8sVersion string, c *C) {
	if !integrationTest {
		c.Skip("Unit test only available with INTEGRATION=1")
	}

	err := k8sversion.Force(k8sVersion)
	c.Assert(err, IsNil)

	cnp := &types.SlimCNP{
		CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "CiliumNetworkPolicy",
				APIVersion: "cilium.io/v2",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testing-policy",
				Namespace: "default",
			},
			Spec: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
		},
	}

	restConfig, err := CreateConfig()
	c.Assert(err, IsNil)
	err = Init(k8sconfig.NewDefaultConfiguration())
	c.Assert(err, IsNil)

	// One client per node
	ciliumNPClients := make([]clientset.Interface, nNodes)
	for i := range ciliumNPClients {
		ciliumNPClients[i], err = clientset.NewForConfig(restConfig)
		c.Assert(err, IsNil)
	}

	cnp.CiliumNetworkPolicy, err = ciliumNPClients[0].CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Create(context.TODO(), cnp.CiliumNetworkPolicy, metav1.CreateOptions{})
	c.Assert(err, IsNil)
	defer func() {
		err = ciliumNPClients[0].CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Delete(context.TODO(), cnp.GetName(), metav1.DeleteOptions{})
		c.Assert(err, IsNil)
	}()

	var cnpStore cache.Store
	// TODO create a cache.Store per node
	si := informer.NewSharedInformerFactory(ciliumNPClients[0], 5*time.Minute)
	ciliumV2Controller := si.Cilium().V2().CiliumNetworkPolicies().Informer()
	cnpStore = ciliumV2Controller.GetStore()
	si.Start(wait.NeverStop)
	var exists bool
	// wait for the cnp created to be in the store
	for !exists {
		_, exists, err = cnpStore.Get(cnp)
		time.Sleep(100 * time.Millisecond)
	}

	wg := sync.WaitGroup{}
	wg.Add(nNodes)
	r := make(chan int, nNodes)
	for i := 0; i < nParallelClients; i++ {
		go func() {
			for i := range r {
				updateContext := &CNPStatusUpdateContext{
					CiliumNPClient: ciliumNPClients[i],
					NodeName:       "k8s" + strconv.Itoa(i),
					WaitForEndpointsAtPolicyRev: func(ctx context.Context, rev uint64) error {
						return nil
					},
				}
				err := updateContext.UpdateStatus(context.Background(), cnp, uint64(i), nil)
				c.Assert(err, IsNil)
				wg.Done()
			}
		}()
	}

	start := time.Now()
	c.ResetTimer()
	for i := 0; i < nNodes; i++ {
		r <- i
	}
	wg.Wait()
	c.StopTimer()
	c.Logf("Test took: %s", time.Since(start))
}

func (k *K8sIntegrationSuite) Benchmark_CNPNodeStatusController_1_10(c *C) {
	nNodes, err := strconv.Atoi(os.Getenv("NODES"))
	c.Assert(err, IsNil)

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of NODES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nNodes)
	benchmarkCNPNodeStatusController(os.Getenv("INTEGRATION") != "", nNodes, nClients, "1.10", c)
}

func (k *K8sIntegrationSuite) Benchmark_CNPNodeStatusController_1_13(c *C) {
	nNodes, err := strconv.Atoi(os.Getenv("NODES"))
	c.Assert(err, IsNil)

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of NODES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nNodes)
	benchmarkCNPNodeStatusController(os.Getenv("INTEGRATION") != "", nNodes, nClients, "1.13", c)
}

func (k *K8sIntegrationSuite) benchmarkUpdateCNPNodeStatus(integrationTest bool, nNodes int, nParallelClients int, k8sVersion string, c *C) {
	err := k8sversion.Force(k8sVersion)
	c.Assert(err, IsNil)
	cnp := &types.SlimCNP{
		CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "CiliumNetworkPolicy",
				APIVersion: "cilium.io/v2",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testing-policy",
				Namespace: "default",
			},
			Spec: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{"foo": "bar"},
					},
				},
			},
		},
	}

	// One client per node
	ciliumNPClients := make([]clientset.Interface, nNodes)
	if integrationTest {
		restConfig, err := CreateConfig()
		c.Assert(err, IsNil)
		for i := range ciliumNPClients {
			ciliumNPClients[i], err = clientset.NewForConfig(restConfig)
			c.Assert(err, IsNil)
		}
		cnp.CiliumNetworkPolicy, err = ciliumNPClients[0].CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Create(context.TODO(), cnp.CiliumNetworkPolicy, metav1.CreateOptions{})
		c.Assert(err, IsNil)
		defer func() {
			err = ciliumNPClients[0].CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()).Delete(context.TODO(), cnp.GetName(), metav1.DeleteOptions{})
			c.Assert(err, IsNil)
		}()
	} else {
		ciliumNPClientFake := &fake.Clientset{}
		ciliumNPClientFake.AddReactor("patch", "ciliumnetworkpolicies",
			func(action k8sTesting.Action) (bool, runtime.Object, error) {
				time.Sleep(1 * time.Millisecond)
				return true, cnp.CiliumNetworkPolicy, nil
			})
		ciliumNPClientFake.AddReactor("get", "ciliumnetworkpolicies",
			func(action k8sTesting.Action) (bool, runtime.Object, error) {
				time.Sleep(1 * time.Millisecond)
				return true, cnp.CiliumNetworkPolicy, nil
			})
		ciliumNPClientFake.AddReactor("update", "ciliumnetworkpolicies",
			func(action k8sTesting.Action) (bool, runtime.Object, error) {
				ua := action.(k8sTesting.UpdateAction)
				cnp := ua.GetObject().(*v2.CiliumNetworkPolicy)
				time.Sleep(1 * time.Millisecond)
				return true, cnp, nil
			})

		for i := range ciliumNPClients {
			ciliumNPClients[i] = ciliumNPClientFake
		}
	}
	wg := sync.WaitGroup{}
	wg.Add(nNodes)
	r := make(chan int, nNodes)
	for i := 0; i < nParallelClients; i++ {
		go func() {
			for i := range r {
				updateContext := &CNPStatusUpdateContext{
					CiliumNPClient: ciliumNPClients[i],
					NodeName:       "k8s" + strconv.Itoa(i),
				}
				err := updateContext.UpdateViaAPIServer(cnp, true, true, nil, uint64(i), nil)
				c.Assert(err, IsNil)
				wg.Done()
			}
		}()
	}

	start := time.Now()
	c.ResetTimer()
	for i := 0; i < nNodes; i++ {
		r <- i
	}
	wg.Wait()
	c.StopTimer()
	c.Logf("Test took: %s", time.Since(start))
}

func (k *K8sIntegrationSuite) Benchmark_UpdateCNPNodeStatus_1_10(c *C) {
	nNodes, err := strconv.Atoi(os.Getenv("NODES"))
	c.Assert(err, IsNil)

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of NODES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nNodes)
	k.benchmarkUpdateCNPNodeStatus(os.Getenv("INTEGRATION") != "", nNodes, nClients, "1.10", c)
}

func (k *K8sIntegrationSuite) Benchmark_UpdateCNPNodeStatus_1_13(c *C) {
	nNodes, err := strconv.Atoi(os.Getenv("NODES"))
	c.Assert(err, IsNil)

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of NODES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nNodes)
	k.benchmarkUpdateCNPNodeStatus(os.Getenv("INTEGRATION") != "", nNodes, nClients, "1.13", c)
}

func (k *K8sIntegrationSuite) benchmarkGetNodes(integrationTest bool, nCycles int, nParallelClients int, protobuf bool, c *C) {

	// One client per node
	k8sClients := make([]kubernetes.Interface, nParallelClients)
	if integrationTest {
		restConfig, err := CreateConfig()
		c.Assert(err, IsNil)
		if protobuf {
			restConfig.ContentConfig.ContentType = `application/vnd.kubernetes.protobuf`
		}
		for i := range k8sClients {
			k8sClients[i], err = kubernetes.NewForConfig(restConfig)
			c.Assert(err, IsNil)
		}
	}
	wg := sync.WaitGroup{}
	wg.Add(nCycles)
	r := make(chan int, nCycles)
	for i := 0; i < nParallelClients; i++ {
		go func(clientID int) {
			for range r {
				_, err := k8sClients[clientID].CoreV1().Nodes().Get(context.TODO(), "k8s1", metav1.GetOptions{})
				c.Assert(err, IsNil)
				wg.Done()
			}
		}(i)
	}

	start := time.Now()
	c.ResetTimer()
	for i := 0; i < nCycles; i++ {
		r <- i
	}
	wg.Wait()
	c.StopTimer()
	c.Logf("Test took: %s", time.Since(start))
}

func (k *K8sIntegrationSuite) Benchmark_GetNodesProto(c *C) {
	nCycles, err := strconv.Atoi(os.Getenv("CYCLES"))
	if err != nil {
		nCycles = c.N
	}

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of CYCLES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nCycles)
	k.benchmarkGetNodes(os.Getenv("INTEGRATION") != "", nCycles, nClients, true, c)
}

func (k *K8sIntegrationSuite) Benchmark_GetNodesJSON(c *C) {
	nCycles, err := strconv.Atoi(os.Getenv("CYCLES"))
	if err != nil {
		nCycles = c.N
	}

	// create nTh parallel clients. We achieve better results if the number
	// of clients are not the same as number of CYCLES. We can simulate 1000 Nodes
	// but we can simulate 1000 clients with a 8 CPU machine.
	nClients := go_runtime.NumCPU()
	if nClientsStr := os.Getenv("PARALLEL_CLIENTS"); nClientsStr != "" {
		nClients, err = strconv.Atoi(nClientsStr)
		c.Assert(err, IsNil)
	}
	c.Logf("Running with %d parallel clients and %d nodes", nClients, nCycles)
	k.benchmarkGetNodes(os.Getenv("INTEGRATION") != "", nCycles, nClients, false, c)
}

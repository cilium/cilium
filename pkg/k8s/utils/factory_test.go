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

package utils

import (
	"log"
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/serializer"
	"github.com/cilium/cilium/pkg/versioned"

	. "gopkg.in/check.v1"
	"k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type FactorySuite struct{}

var _ = Suite(&FactorySuite{})

func init() {
	RegisterObject(
		&v1.NetworkPolicy{},
		"networkpolicies",
		copyObjToTestObject,
		listTestObject,
		equalTestObject,
	)
}

func listTestObject(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(kubernetes.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'kubernetes.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		list, err := k8sClient.NetworkingV1().NetworkPolicies("").List(meta_v1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			m.Add(GetVerStructFrom(&list.Items[i]))
		}
		return m, nil
	}
}

func copyObjToTestObject(obj interface{}) meta_v1.Object {
	k8sNP, ok := obj.(*v1.NetworkPolicy)
	if !ok {
		return nil
	}
	return k8sNP.DeepCopy()
}

func equalTestObject(o1, o2 interface{}) bool {
	np1, ok := o1.(*v1.NetworkPolicy)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.NetworkPolicy", reflect.TypeOf(o1))
		return false
	}
	np2, ok := o2.(*v1.NetworkPolicy)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.NetworkPolicy", reflect.TypeOf(o2))
		return false
	}
	// As Cilium uses all of the Spec from a NP it's not probably not worth
	// it to create a dedicated deep equal	 function to compare both network
	// policies.
	return np1.Name == np2.Name &&
		np1.Namespace == np2.Namespace &&
		reflect.DeepEqual(np1.Spec, np2.Spec)
}

func (s *FactorySuite) Test_replaceFuncFactory(c *C) {
	type args struct {
		listerClient interface{}
		resourceObj  runtime.Object
		addFunc      func(i interface{}) func() error
		delFunc      func(i interface{}) func() error
		missingFunc  func(comparableMap versioned.Map) versioned.Map
		fqueue       *serializer.FunctionQueue
		addFuncCalls *int
		delFuncCalls *int
	}
	type want struct {
		oldMap       *versioned.ComparableMap
		newMap       *versioned.ComparableMap
		addFuncCalls int
		delFuncCalls int
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
	}{
		{
			name: "missing NetworkPolicy from the repository. When doing a re-sync Cilium should get an AddEvent",
			setupArgs: func() args {
				addFuncCalls := 0
				delFuncCalls := 0

				k8sClient := &fake.Clientset{}
				k8sClient.AddReactor("list", "networkpolicies",
					func(action k8sTesting.Action) (bool, runtime.Object, error) {
						la := action.(k8sTesting.ListAction)
						c.Assert(la.GetNamespace(), Equals, "")
						list := &v1.NetworkPolicyList{}
						list.Items = append(list.Items, v1.NetworkPolicy{
							ObjectMeta: meta_v1.ObjectMeta{
								Name:            "foo",
								Namespace:       "bar",
								UID:             "1234",
								ResourceVersion: "12",
							},
						})
						return true, list, nil
					})
				addFunc := func(i interface{}) func() error {
					obj, ok := i.(*v1.NetworkPolicy)
					c.Assert(ok, Equals, true)
					wanted := &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:            "foo",
							Namespace:       "bar",
							UID:             "1234",
							ResourceVersion: "12",
						},
					}
					c.Assert(obj, DeepEquals, wanted, Commentf("NetworkPolicy added should be exactly the same from kube-apiserver"))
					addFuncCalls++
					return func() error {
						return nil
					}
				}
				delFunc := func(i interface{}) func() error {
					delFuncCalls++
					return func() error {
						return nil
					}
				}
				fqueue := serializer.NewFunctionQueue(1024)

				missingFunc := func(m versioned.Map) versioned.Map {
					// returns the same received map because it's missing from
					// the local repository
					return m
				}

				return args{
					listerClient: k8sClient,
					resourceObj:  &v1.NetworkPolicy{},
					addFunc:      addFunc,
					delFunc:      delFunc,
					missingFunc:  missingFunc,
					fqueue:       fqueue,
					addFuncCalls: &addFuncCalls,
					delFuncCalls: &delFuncCalls,
				}
			},
			setupWant: func() want {
				newMap := versioned.NewComparableMap(nil)
				// NewMap should contain the missing NetworkPolicy
				newMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:            "foo",
							Namespace:       "bar",
							UID:             "1234",
							ResourceVersion: "12",
						},
					},
					Version: versioned.Version(12),
				})
				return want{
					oldMap:       versioned.NewComparableMap(equalTestObject),
					newMap:       newMap,
					addFuncCalls: 1,
				}
			},
		},
		{
			name: "Cilium missed a Delete event from k8s, when doing a re-sync it should get a Delete event",
			setupArgs: func() args {
				addFuncCalls := 0
				delFuncCalls := 0

				k8sClient := &fake.Clientset{}
				k8sClient.AddReactor("list", "networkpolicies",
					func(action k8sTesting.Action) (bool, runtime.Object, error) {
						la := action.(k8sTesting.ListAction)
						c.Assert(la.GetNamespace(), Equals, "")
						list := &v1.NetworkPolicyList{}
						return true, list, nil
					})
				addFunc := func(i interface{}) func() error {
					addFuncCalls++
					return func() error {
						return nil
					}
				}
				delFunc := func(i interface{}) func() error {
					obj, ok := i.(*v1.NetworkPolicy)
					c.Assert(ok, Equals, true)
					wanted := &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:            "foo",
							Namespace:       "bar",
							UID:             "1234",
							ResourceVersion: "12",
						},
					}
					c.Assert(obj, DeepEquals, wanted, Commentf("NetworkPolicy deleted should be exactly that is missing from kube-apiserver"))
					delFuncCalls++
					return func() error {
						return nil
					}
				}
				fqueue := serializer.NewFunctionQueue(1024)

				missingFunc := func(m versioned.Map) versioned.Map {
					// missingFunc will be called with all objects that should
					// exist locally.
					c.Assert(m, DeepEquals, versioned.NewMap())
					return m
				}

				return args{
					listerClient: k8sClient,
					resourceObj:  &v1.NetworkPolicy{},
					addFunc:      addFunc,
					delFunc:      delFunc,
					missingFunc:  missingFunc,
					fqueue:       fqueue,
					addFuncCalls: &addFuncCalls,
					delFuncCalls: &delFuncCalls,
				}
			},
			setupWant: func() want {
				oldMap := versioned.NewComparableMap(nil)
				// oldMap will contain a Network Policy that should have been deleted
				oldMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:            "foo",
							Namespace:       "bar",
							UID:             "1234",
							ResourceVersion: "12",
						},
					},
					Version: versioned.Version(12),
				})
				return want{
					oldMap:       oldMap,
					newMap:       versioned.NewComparableMap(equalTestObject),
					delFuncCalls: 1,
				}
			},
		},
		{
			name: "Cilium is already synced so a no-op should be executed for a field changed that Cilium doesn't care",
			setupArgs: func() args {
				addFuncCalls := 0
				delFuncCalls := 0

				k8sClient := &fake.Clientset{}
				k8sClient.AddReactor("list", "networkpolicies",
					func(action k8sTesting.Action) (bool, runtime.Object, error) {
						la := action.(k8sTesting.ListAction)
						c.Assert(la.GetNamespace(), Equals, "")
						list := &v1.NetworkPolicyList{}
						list.Items = append(list.Items, v1.NetworkPolicy{
							ObjectMeta: meta_v1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
								UID:       "1234",
								Labels: map[string]string{
									"useless": "label",
								},
								ResourceVersion: "13",
							},
						})
						return true, list, nil
					})
				addFunc := func(i interface{}) func() error {
					addFuncCalls++
					return func() error {
						return nil
					}
				}
				delFunc := func(i interface{}) func() error {
					delFuncCalls++
					return func() error {
						return nil
					}
				}
				fqueue := serializer.NewFunctionQueue(1024)

				missingFunc := func(m versioned.Map) versioned.Map {
					newMap := versioned.NewMap()
					newMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
						Data: &v1.NetworkPolicy{
							ObjectMeta: meta_v1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
								UID:       "1234",
								Labels: map[string]string{
									"useless": "label",
								},
								ResourceVersion: "13",
							},
						},
						Version: versioned.Version(13),
					})
					// missingFunc will be called with all objects that should
					// exist locally.
					c.Assert(m, DeepEquals, newMap)
					return nil
				}

				return args{
					listerClient: k8sClient,
					resourceObj:  &v1.NetworkPolicy{},
					addFunc:      addFunc,
					delFunc:      delFunc,
					missingFunc:  missingFunc,
					fqueue:       fqueue,
					addFuncCalls: &addFuncCalls,
					delFuncCalls: &delFuncCalls,
				}
			},
			setupWant: func() want {

				oldMap := versioned.NewComparableMap(equalTestObject)
				oldMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:            "foo",
							Namespace:       "bar",
							UID:             "1234",
							ResourceVersion: "12",
						},
					},
					Version: versioned.Version(12),
				})

				newMap := versioned.NewComparableMap(nil)
				// NewMap will contain the updated network policy with the
				// new "useless" label. As Cilium doesn't need the labels
				// no Add/Del Funcs should be called.
				newMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
							UID:       "1234",
							Labels: map[string]string{
								"useless": "label",
							},
							ResourceVersion: "13",
						},
					},
					Version: versioned.Version(13),
				})

				return want{
					oldMap: oldMap,
					newMap: newMap,
				}
			},
		},
		{
			name: "Cilium is not synced with kube-apiserver. When a field, that Cilium cares about, " +
				"was modified then it needs to send an AddFunc event",
			setupArgs: func() args {
				addFuncCalls := 0
				delFuncCalls := 0

				k8sClient := &fake.Clientset{}
				k8sClient.AddReactor("list", "networkpolicies",
					func(action k8sTesting.Action) (bool, runtime.Object, error) {
						la := action.(k8sTesting.ListAction)
						c.Assert(la.GetNamespace(), Equals, "")
						list := &v1.NetworkPolicyList{}
						list.Items = append(list.Items, v1.NetworkPolicy{
							ObjectMeta: meta_v1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
								UID:       "1234",
								Labels: map[string]string{
									"useless": "label",
								},
								ResourceVersion: "13",
							},
							Spec: v1.NetworkPolicySpec{
								PodSelector: meta_v1.LabelSelector{
									MatchLabels: map[string]string{
										"labels": "that-matter",
									},
								},
							},
						})
						return true, list, nil
					})
				addFunc := func(i interface{}) func() error {
					obj, ok := i.(*v1.NetworkPolicy)
					c.Assert(ok, Equals, true)
					wanted := &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
							UID:       "1234",
							Labels: map[string]string{
								"useless": "label",
							},
							ResourceVersion: "13",
						},
						Spec: v1.NetworkPolicySpec{
							PodSelector: meta_v1.LabelSelector{
								MatchLabels: map[string]string{
									"labels": "that-matter",
								},
							},
						},
					}
					c.Assert(obj, DeepEquals, wanted, Commentf("NetworkPolicy deleted should be exactly that is missing from kube-apiserver"))
					addFuncCalls++
					return func() error {
						return nil
					}
				}
				delFunc := func(i interface{}) func() error {
					delFuncCalls++
					return func() error {
						return nil
					}
				}
				fqueue := serializer.NewFunctionQueue(1024)

				missingFunc := func(m versioned.Map) versioned.Map {
					newMap := versioned.NewMap()
					newMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
						Data: &v1.NetworkPolicy{
							ObjectMeta: meta_v1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
								UID:       "1234",
								Labels: map[string]string{
									"useless": "label",
								},
								ResourceVersion: "13",
							},
							Spec: v1.NetworkPolicySpec{
								PodSelector: meta_v1.LabelSelector{
									MatchLabels: map[string]string{
										"labels": "that-matter",
									},
								},
							},
						},
						Version: versioned.Version(13),
					})
					// missingFunc will be called with all objects that should
					// exist locally.
					c.Assert(m, DeepEquals, newMap)
					return nil
				}

				return args{
					listerClient: k8sClient,
					resourceObj:  &v1.NetworkPolicy{},
					addFunc:      addFunc,
					delFunc:      delFunc,
					missingFunc:  missingFunc,
					fqueue:       fqueue,
					addFuncCalls: &addFuncCalls,
					delFuncCalls: &delFuncCalls,
				}
			},
			setupWant: func() want {

				oldMap := versioned.NewComparableMap(equalTestObject)
				oldMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:            "foo",
							Namespace:       "bar",
							UID:             "1234",
							ResourceVersion: "12",
						},
					},
					Version: versioned.Version(12),
				})

				newMap := versioned.NewComparableMap(nil)
				// NewMap will contain the updated network policy
				newMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
							UID:       "1234",
							Labels: map[string]string{
								"useless": "label",
							},
							ResourceVersion: "13",
						},
						Spec: v1.NetworkPolicySpec{
							PodSelector: meta_v1.LabelSelector{
								MatchLabels: map[string]string{
									"labels": "that-matter",
								},
							},
						},
					},
					Version: versioned.Version(13),
				})

				return want{
					oldMap:       oldMap,
					newMap:       newMap,
					addFuncCalls: 1,
				}
			},
		},
		{
			name: "Cilium already processed an event with a newer resource version so it will discard anything from the lister",
			setupArgs: func() args {
				addFuncCalls := 0
				delFuncCalls := 0

				k8sClient := &fake.Clientset{}
				k8sClient.AddReactor("list", "networkpolicies",
					func(action k8sTesting.Action) (bool, runtime.Object, error) {
						la := action.(k8sTesting.ListAction)
						c.Assert(la.GetNamespace(), Equals, "")
						list := &v1.NetworkPolicyList{}
						list.Items = append(list.Items, v1.NetworkPolicy{
							ObjectMeta: meta_v1.ObjectMeta{
								Name:      "foo",
								Namespace: "bar",
								UID:       "1234",
								Labels: map[string]string{
									"useless": "label",
								},
								ResourceVersion: "13",
							},
							Spec: v1.NetworkPolicySpec{
								PodSelector: meta_v1.LabelSelector{
									MatchLabels: map[string]string{
										"labels": "that-matter",
									},
								},
							},
						})
						return true, list, nil
					})
				addFunc := func(i interface{}) func() error {
					addFuncCalls++
					return func() error {
						return nil
					}
				}
				delFunc := func(i interface{}) func() error {
					delFuncCalls++
					return func() error {
						return nil
					}
				}
				fqueue := serializer.NewFunctionQueue(1024)

				missingFunc := func(m versioned.Map) versioned.Map {
					wanted := versioned.NewMap()
					wanted.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
						Data: &v1.NetworkPolicy{
							ObjectMeta: meta_v1.ObjectMeta{
								Name:            "foo",
								Namespace:       "bar",
								UID:             "1234",
								ResourceVersion: "14",
							},
						},
						Version: versioned.Version(14),
					})
					// missingFunc will be called with all objects that should
					// exist locally.
					c.Assert(m, DeepEquals, wanted)
					return nil
				}

				return args{
					listerClient: k8sClient,
					resourceObj:  &v1.NetworkPolicy{},
					addFunc:      addFunc,
					delFunc:      delFunc,
					missingFunc:  missingFunc,
					fqueue:       fqueue,
					addFuncCalls: &addFuncCalls,
					delFuncCalls: &delFuncCalls,
				}
			},
			setupWant: func() want {

				oldMap := versioned.NewComparableMap(equalTestObject)
				oldMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:            "foo",
							Namespace:       "bar",
							UID:             "1234",
							ResourceVersion: "14",
						},
					},
					Version: versioned.Version(14),
				})

				newMap := versioned.NewComparableMap(nil)
				// NewMap will contain the updated network policy
				newMap.Add(versioned.UUID("bar/foo/1234"), versioned.Object{
					Data: &v1.NetworkPolicy{
						ObjectMeta: meta_v1.ObjectMeta{
							Name:            "foo",
							Namespace:       "bar",
							UID:             "1234",
							ResourceVersion: "14",
						},
					},
					Version: versioned.Version(14),
				})

				return want{
					oldMap: oldMap,
					newMap: newMap,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		replaceFunc := replaceFuncFactory(args.listerClient, args.resourceObj, args.addFunc, args.delFunc, args.missingFunc, args.fqueue)
		newMap, err := replaceFunc(want.oldMap)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		c.Assert(newMap.Map, DeepEquals, want.newMap.Map, Commentf("Test Name: %s", tt.name))
		c.Assert(*args.addFuncCalls, Equals, want.addFuncCalls, Commentf("Test Name: %s", tt.name))
		c.Assert(*args.delFuncCalls, Equals, want.delFuncCalls, Commentf("Test Name: %s", tt.name))
	}
}

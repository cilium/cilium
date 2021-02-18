// Copyright 2016-2017 Authors of Cilium
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

package labels

import (
	"github.com/cilium/cilium/pkg/checker"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type LabelsPrefCfgSuite struct{}

var _ = Suite(&LabelsPrefCfgSuite{})

func (s *LabelsPrefCfgSuite) TestFilterLabels(c *C) {
	wanted := Labels{
		"id.lizards":                  NewLabel("id.lizards", "web", LabelSourceContainer),
		"id.lizards.k8s":              NewLabel("id.lizards.k8s", "web", LabelSourceK8s),
		"io.kubernetes.pod.namespace": NewLabel("io.kubernetes.pod.namespace", "default", LabelSourceContainer),
		"app.kubernetes.io":           NewLabel("app.kubernetes.io", "my-nginx", LabelSourceContainer),
		"foo2.lizards.k8s":            NewLabel("foo2.lizards.k8s", "web", LabelSourceK8s),
	}

	err := ParseLabelPrefixCfg([]string{":!ignor[eE]", "id.*", "foo"}, "")
	c.Assert(err, IsNil)
	dlpcfg := validLabelPrefixes
	allNormalLabels := map[string]string{
		"io.kubernetes.container.hash":                              "cf58006d",
		"io.kubernetes.container.name":                              "POD",
		"io.kubernetes.container.restartCount":                      "0",
		"io.kubernetes.container.terminationMessagePath":            "",
		"io.kubernetes.pod.name":                                    "my-nginx-3800858182-07i3n",
		"io.kubernetes.pod.namespace":                               "default",
		"app.kubernetes.io":                                         "my-nginx",
		"kubernetes.io.foo":                                         "foo",
		"beta.kubernetes.io.foo":                                    "foo",
		"annotation.kubectl.kubernetes.io":                          "foo",
		"annotation.hello":                                          "world",
		"annotation." + k8sConst.CiliumIdentityAnnotationDeprecated: "12356",
		"io.kubernetes.pod.terminationGracePeriod":                  "30",
		"io.kubernetes.pod.uid":                                     "c2e22414-dfc3-11e5-9792-080027755f5a",
		"ignore":                                                    "foo",
		"ignorE":                                                    "foo",
		"annotation.kubernetes.io/config.seen":                      "2017-05-30T14:22:17.691491034Z",
		"controller-revision-hash":                                  "123456",
	}
	allLabels := Map2Labels(allNormalLabels, LabelSourceContainer)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 2)
	allLabels["id.lizards"] = NewLabel("id.lizards", "web", LabelSourceContainer)
	allLabels["id.lizards.k8s"] = NewLabel("id.lizards.k8s", "web", LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 4)
	// Checking that it does not need to an exact match of "foo", but "foo2" also works since it's not a regex
	allLabels["foo2.lizards.k8s"] = NewLabel("foo2.lizards.k8s", "web", LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 5)
	// Checking that "foo" only works if it's the prefix of a label
	allLabels["lizards.foo.lizards.k8s"] = NewLabel("lizards.foo.lizards.k8s", "web", LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 5)
	c.Assert(filtered, checker.DeepEquals, wanted)
	// Making sure we are deep copying the labels
	allLabels["id.lizards"] = NewLabel("id.lizards", "web", "I can change this and doesn't affect any one")
	c.Assert(filtered, checker.DeepEquals, wanted)
}

func (s *LabelsPrefCfgSuite) TestDefaultFilterLabels(c *C) {
	wanted := Labels{
		"app.kubernetes.io":           NewLabel("app.kubernetes.io", "my-nginx", LabelSourceContainer),
		"id.lizards.k8s":              NewLabel("id.lizards.k8s", "web", LabelSourceK8s),
		"id.lizards":                  NewLabel("id.lizards", "web", LabelSourceContainer),
		"ignorE":                      NewLabel("ignorE", "foo", LabelSourceContainer),
		"ignore":                      NewLabel("ignore", "foo", LabelSourceContainer),
		"reserved:host":               NewLabel("reserved:host", "", LabelSourceAny),
		"io.kubernetes.pod.namespace": NewLabel("io.kubernetes.pod.namespace", "default", LabelSourceContainer),
	}

	err := ParseLabelPrefixCfg([]string{}, "")
	c.Assert(err, IsNil)
	dlpcfg := validLabelPrefixes
	allNormalLabels := map[string]string{
		"io.kubernetes.container.hash":                              "cf58006d",
		"io.kubernetes.container.name":                              "POD",
		"io.kubernetes.container.restartCount":                      "0",
		"io.kubernetes.container.terminationMessagePath":            "",
		"io.kubernetes.pod.name":                                    "my-nginx-3800858182-07i3n",
		"io.kubernetes.pod.namespace":                               "default",
		"app.kubernetes.io":                                         "my-nginx",
		"kubernetes.io.foo":                                         "foo",
		"beta.kubernetes.io.foo":                                    "foo",
		"annotation.kubectl.kubernetes.io":                          "foo",
		"annotation.hello":                                          "world",
		"annotation." + k8sConst.CiliumIdentityAnnotationDeprecated: "12356",
		"io.kubernetes.pod.terminationGracePeriod":                  "30",
		"io.kubernetes.pod.uid":                                     "c2e22414-dfc3-11e5-9792-080027755f5a",
		"ignore":                                                    "foo",
		"ignorE":                                                    "foo",
		"annotation.kubernetes.io/config.seen":                      "2017-05-30T14:22:17.691491034Z",
		"controller-revision-hash":                                  "123456",
	}
	allLabels := Map2Labels(allNormalLabels, LabelSourceContainer)
	allLabels["reserved:host"] = NewLabel("reserved:host", "", LabelSourceAny)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 5)
	allLabels["id.lizards"] = NewLabel("id.lizards", "web", LabelSourceContainer)
	allLabels["id.lizards.k8s"] = NewLabel("id.lizards.k8s", "web", LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 7)
	c.Assert(filtered, checker.DeepEquals, wanted)
}

func (s *LabelsPrefCfgSuite) TestFilterLabelsDocExample(c *C) {
	wanted := Labels{
		"io.cilium.k8s.namespace.labels": NewLabel("io.cilium.k8s.namespace.labels", "foo", LabelSourceK8s),
		"k8s-app-team":                   NewLabel("k8s-app-team", "foo", LabelSourceK8s),
		"app-production":                 NewLabel("app-production", "foo", LabelSourceK8s),
		"name-defined":                   NewLabel("name-defined", "foo", LabelSourceK8s),
		"io.kubernetes.pod.namespace":    NewLabel("io.kubernetes.pod.namespace", "docker", LabelSourceAny),
	}

	err := ParseLabelPrefixCfg([]string{"k8s:io.kubernetes.pod.namespace", "k8s:k8s-app", "k8s:app", "k8s:name"}, "")
	c.Assert(err, IsNil)
	dlpcfg := validLabelPrefixes
	allNormalLabels := map[string]string{
		"io.cilium.k8s.namespace.labels": "foo",
		"k8s-app-team":                   "foo",
		"app-production":                 "foo",
		"name-defined":                   "foo",
	}
	allLabels := Map2Labels(allNormalLabels, LabelSourceK8s)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 4)

	// Reserved labels are not included.
	allLabels["host"] = NewLabel("host", "", LabelSourceReserved)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 4)

	// io.kubernetes.pod.namespace=docker matches because the default list has any:io.kubernetes.pod.namespace.
	allLabels["io.kubernetes.pod.namespace"] = NewLabel("io.kubernetes.pod.namespace", "docker", LabelSourceAny)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 5)

	// container:k8s-app-role=foo doesn't match because it doesn't have source k8s.
	allLabels["k8s-app-role"] = NewLabel("k8s-app-role", "foo", LabelSourceContainer)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 5)
	c.Assert(filtered, checker.DeepEquals, wanted)
}

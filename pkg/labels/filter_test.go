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
	}

	dlpcfg := defaultLabelPrefixCfg()
	d, err := parseLabelPrefix(":!ignor[eE]")
	c.Assert(err, IsNil)
	c.Assert(d, Not(IsNil))
	dlpcfg.LabelPrefixes = append(dlpcfg.LabelPrefixes, d)
	d, err = parseLabelPrefix("id.*")
	c.Assert(err, IsNil)
	c.Assert(d, Not(IsNil))
	dlpcfg.LabelPrefixes = append(dlpcfg.LabelPrefixes, d)
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
	c.Assert(filtered, checker.DeepEquals, wanted)
	// Making sure we are deep copying the labels
	allLabels["id.lizards"] = NewLabel("id.lizards", "web", "I can change this and doesn't affect any one")
	c.Assert(filtered, checker.DeepEquals, wanted)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilter

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LabelsPrefCfgSuite struct{}

var _ = Suite(&LabelsPrefCfgSuite{})

func (s *LabelsPrefCfgSuite) TestFilterLabels(c *C) {
	wanted := labels.Labels{
		"id.lizards":                  labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer),
		"id.lizards.k8s":              labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s),
		"io.kubernetes.pod.namespace": labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceContainer),
		"app.kubernetes.io":           labels.NewLabel("app.kubernetes.io", "my-nginx", labels.LabelSourceContainer),
		"foo2.lizards.k8s":            labels.NewLabel("foo2.lizards.k8s", "web", labels.LabelSourceK8s),
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
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceContainer)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 2)
	allLabels["id.lizards"] = labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer)
	allLabels["id.lizards.k8s"] = labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 4)
	// Checking that it does not need to an exact match of "foo", but "foo2" also works since it's not a regex
	allLabels["foo2.lizards.k8s"] = labels.NewLabel("foo2.lizards.k8s", "web", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 5)
	// Checking that "foo" only works if it's the prefix of a label
	allLabels["lizards.foo.lizards.k8s"] = labels.NewLabel("lizards.foo.lizards.k8s", "web", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 5)
	c.Assert(filtered, checker.DeepEquals, wanted)
	// Making sure we are deep copying the labels
	allLabels["id.lizards"] = labels.NewLabel("id.lizards", "web", "I can change this and doesn't affect any one")
	c.Assert(filtered, checker.DeepEquals, wanted)
}

func (s *LabelsPrefCfgSuite) TestDefaultFilterLabels(c *C) {
	wanted := labels.Labels{
		"app.kubernetes.io":           labels.NewLabel("app.kubernetes.io", "my-nginx", labels.LabelSourceContainer),
		"id.lizards.k8s":              labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s),
		"id.lizards":                  labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer),
		"ignorE":                      labels.NewLabel("ignorE", "foo", labels.LabelSourceContainer),
		"ignore":                      labels.NewLabel("ignore", "foo", labels.LabelSourceContainer),
		"host":                        labels.NewLabel("host", "", labels.LabelSourceReserved),
		"io.kubernetes.pod.namespace": labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceContainer),
		"ioXkubernetes":               labels.NewLabel("ioXkubernetes", "foo", labels.LabelSourceContainer),
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
		"ioXkubernetes":                                             "foo",
		"ignore":                                                    "foo",
		"ignorE":                                                    "foo",
		"annotation.kubernetes.io/config.seen":                      "2017-05-30T14:22:17.691491034Z",
		"controller-revision-hash":                                  "123456",
	}
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceContainer)
	allLabels["host"] = labels.NewLabel("host", "", labels.LabelSourceReserved)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, len(wanted)-2) // -2 because we add two labels in the next lines
	allLabels["id.lizards"] = labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer)
	allLabels["id.lizards.k8s"] = labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(filtered, checker.DeepEquals, wanted)
}

func (s *LabelsPrefCfgSuite) TestFilterLabelsDocExample(c *C) {
	wanted := labels.Labels{
		"io.cilium.k8s.namespace.labels": labels.NewLabel("io.cilium.k8s.namespace.labels", "foo", labels.LabelSourceK8s),
		"k8s-app-team":                   labels.NewLabel("k8s-app-team", "foo", labels.LabelSourceK8s),
		"app-production":                 labels.NewLabel("app-production", "foo", labels.LabelSourceK8s),
		"name-defined":                   labels.NewLabel("name-defined", "foo", labels.LabelSourceK8s),
		"host":                           labels.NewLabel("host", "", labels.LabelSourceReserved),
		"io.kubernetes.pod.namespace":    labels.NewLabel("io.kubernetes.pod.namespace", "docker", labels.LabelSourceAny),
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
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceK8s)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 4)

	// Reserved labels are included.
	allLabels["host"] = labels.NewLabel("host", "", labels.LabelSourceReserved)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 5)

	// io.kubernetes.pod.namespace=docker matches because the default list has any:io.kubernetes.pod.namespace.
	allLabels["io.kubernetes.pod.namespace"] = labels.NewLabel("io.kubernetes.pod.namespace", "docker", labels.LabelSourceAny)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 6)

	// container:k8s-app-role=foo doesn't match because it doesn't have source k8s.
	allLabels["k8s-app-role"] = labels.NewLabel("k8s-app-role", "foo", labels.LabelSourceContainer)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	c.Assert(len(filtered), Equals, 6)
	c.Assert(filtered, checker.DeepEquals, wanted)
}

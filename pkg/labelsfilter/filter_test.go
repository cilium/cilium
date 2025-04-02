// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilter

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

func TestFilterLabels(t *testing.T) {
	wanted := labels.NewLabels(labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer),
		labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s),
		labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceContainer),
		labels.NewLabel("app.kubernetes.io", "my-nginx", labels.LabelSourceContainer),
		labels.NewLabel("foo2.lizards.k8s", "web", labels.LabelSourceK8s),
		labels.NewLabel("io.cilium.k8s.policy.cluster", "default", labels.LabelSourceContainer))

	err := ParseLabelPrefixCfg([]string{":!ignor[eE]", "id.*", "foo"}, []string{}, "")
	require.NoError(t, err)
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
		"io.cilium.k8s.policy.cluster":                              "default",
	}
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceContainer)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 3)
	allLabels = allLabels.Add(labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer))
	allLabels = allLabels.Add(labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s))
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 5)
	// Checking that it does not need to an exact match of "foo", but "foo2" also works since it's not a regex
	allLabels = allLabels.Add(labels.NewLabel("foo2.lizards.k8s", "web", labels.LabelSourceK8s))
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 6)
	// Checking that "foo" only works if it's the prefix of a label
	allLabels = allLabels.Add(labels.NewLabel("lizards.foo.lizards.k8s", "web", labels.LabelSourceK8s))
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 6)
	require.EqualValues(t, wanted, filtered)
	// Making sure we are deep copying the labels
	allLabels = allLabels.Add(labels.NewLabel("id.lizards", "web", "I can change this and doesn't affect any one"))
	require.EqualValues(t, wanted, filtered)
}

func TestDefaultFilterLabels(t *testing.T) {
	wanted := labels.NewLabels(labels.NewLabel("app.kubernetes.io", "my-nginx", labels.LabelSourceContainer),
		labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s),
		labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer),
		labels.NewLabel("ignorE", "foo", labels.LabelSourceContainer),
		labels.NewLabel("ignore", "foo", labels.LabelSourceContainer),
		labels.NewLabel("host", "", labels.LabelSourceReserved),
		labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceContainer),
		labels.NewLabel("ioXkubernetes", "foo", labels.LabelSourceContainer),
		labels.NewLabel("io.cilium.k8s.policy.cluster", "default", labels.LabelSourceContainer))

	err := ParseLabelPrefixCfg([]string{}, []string{}, "")
	require.NoError(t, err)
	dlpcfg := validLabelPrefixes
	allNormalLabels := map[string]string{
		"io.kubernetes.container.hash":                              "cf58006d",
		"io.kubernetes.container.name":                              "POD",
		"io.kubernetes.container.restartCount":                      "0",
		"io.kubernetes.container.terminationMessagePath":            "",
		"io.kubernetes.pod.name":                                    "my-nginx-0",
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
		"statefulset.kubernetes.io/pod-name":                        "my-nginx-0",
		"batch.kubernetes.io/job-completion-index":                  "42",
		"apps.kubernetes.io/pod-index":                              "0",
		"io.cilium.k8s.policy.cluster":                              "default",
	}
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceContainer)
	allLabels = allLabels.Add(labels.NewLabel("host", "", labels.LabelSourceReserved))
	filtered, _ := dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, wanted.Len()-2) // -2 because we add two labels in the next lines
	allLabels = allLabels.Add(labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer))
	allLabels = allLabels.Add(labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s))
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.EqualValues(t, wanted, filtered)
}

func TestFilterLabelsDocExample(t *testing.T) {
	wanted := labels.NewLabels(labels.NewLabel("k8s-app-team", "foo", labels.LabelSourceK8s),
		labels.NewLabel("app-production", "foo", labels.LabelSourceK8s),
		labels.NewLabel("name-defined", "foo", labels.LabelSourceK8s),
		labels.NewLabel("kind", "foo", labels.LabelSourceK8s),
		labels.NewLabel("other", "foo", labels.LabelSourceK8s),
		labels.NewLabel("host", "", labels.LabelSourceReserved),
		labels.NewLabel("io.kubernetes.pod.namespace", "docker", labels.LabelSourceK8s))

	err := ParseLabelPrefixCfg([]string{"k8s:io.kubernetes.pod.namespace", "k8s:k8s-app", "k8s:app", "k8s:name", "k8s:kind", "k8s:other"}, []string{}, "")
	require.NoError(t, err)
	dlpcfg := validLabelPrefixes
	allNormalLabels := map[string]string{
		"k8s-app-team":   "foo",
		"app-production": "foo",
		"name-defined":   "foo",
		"kind":           "foo",
		"other":          "foo",
	}
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceK8s)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 5)

	// Reserved labels are included.
	allLabels = allLabels.Add(labels.NewLabel("host", "", labels.LabelSourceReserved))
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 6)

	// io.kubernetes.pod.namespace=docker matches because the default list has k8s:io.kubernetes.pod.namespace.
	allLabels = allLabels.Add(labels.NewLabel("io.kubernetes.pod.namespace", "docker", labels.LabelSourceK8s))
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 7)

	// container:k8s-app-role=foo doesn't match because it doesn't have source k8s.
	allLabels = allLabels.Add(labels.NewLabel("k8s-app-role", "foo", labels.LabelSourceContainer))
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 7)
	require.EqualValues(t, wanted, filtered)
}

func TestFilterLabelsByRegex(t *testing.T) {
	type args struct {
		excludePatterns []*regexp.Regexp
		labels          map[string]string
	}
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "exclude_test",
			args: args{
				[]*regexp.Regexp{regexp.MustCompile("foobar.*")},
				map[string]string{
					"topology.kubernetes.io/region": "us-east-1",
					"foobar.com":                    "unwanted-label",
				},
			},
			want: map[string]string{
				"topology.kubernetes.io/region": "us-east-1",
			},
		},
		{
			name: "multi_exclude_test",
			args: args{
				[]*regexp.Regexp{
					regexp.MustCompile("foo.*"),
					regexp.MustCompile("bar.*"),
				},
				map[string]string{
					"topology.kubernetes.io/region": "us-east-1",
					"foo.com":                       "unwanted-label",
					"bar.com":                       "unwanted-label",
				},
			},
			want: map[string]string{
				"topology.kubernetes.io/region": "us-east-1",
			},
		},
		{
			name: "baseline_test",
			args: args{
				[]*regexp.Regexp{},
				map[string]string{
					"topology.kubernetes.io/region": "us-east-1",
					"foobar.com":                    "unwanted-label",
				},
			},
			want: map[string]string{
				"topology.kubernetes.io/region": "us-east-1",
				"foobar.com":                    "unwanted-label",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterLabelsByRegex(tt.args.excludePatterns, tt.args.labels); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterLabelsByRegex() = %v, want %v", got, tt.want)
			}
		})
	}
}

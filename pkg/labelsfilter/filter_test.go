// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilter

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

func TestFilterLabels(t *testing.T) {
	wanted := labels.Labels{
		"id.lizards":                          labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer),
		"id.lizards.k8s":                      labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s),
		"io.kubernetes.pod.namespace":         labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceContainer),
		"app.kubernetes.io":                   labels.NewLabel("app.kubernetes.io", "my-nginx", labels.LabelSourceContainer),
		"foo2.lizards.k8s":                    labels.NewLabel("foo2.lizards.k8s", "web", labels.LabelSourceK8s),
		"io.cilium.k8s.policy.cluster":        labels.NewLabel("io.cilium.k8s.policy.cluster", "default", labels.LabelSourceContainer),
		"io.cilium.k8s.policy.serviceaccount": labels.NewLabel("io.cilium.k8s.policy.serviceaccount", "luke", labels.LabelSourceContainer),
	}

	err := ParseLabelPrefixCfg(hivetest.Logger(t), []string{":!ignor[eE]", "id.*", "foo"}, []string{}, "")
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
		"io.cilium.k8s.policy.serviceaccount":                       "luke",
	}
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceContainer)
	filtered, _ := dlpcfg.filterLabels(allLabels)

	require.Len(t, filtered, 4)
	allLabels["id.lizards"] = labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer)
	allLabels["id.lizards.k8s"] = labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 6)
	// Checking that it does not need to an exact match of "foo", but "foo2" also works since it's not a regex
	allLabels["foo2.lizards.k8s"] = labels.NewLabel("foo2.lizards.k8s", "web", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 7)
	// Checking that "foo" only works if it's the prefix of a label
	allLabels["lizards.foo.lizards.k8s"] = labels.NewLabel("lizards.foo.lizards.k8s", "web", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 7)
	require.Equal(t, wanted, filtered)
	// Making sure we are deep copying the labels
	allLabels["id.lizards"] = labels.NewLabel("id.lizards", "web", "I can change this and doesn't affect any one")
	require.Equal(t, wanted, filtered)
}

func TestDefaultFilterLabels(t *testing.T) {
	logger := hivetest.Logger(t)
	wanted := labels.Labels{
		"app.kubernetes.io":                   labels.NewLabel("app.kubernetes.io", "my-nginx", labels.LabelSourceContainer),
		"id.lizards.k8s":                      labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s),
		"id.lizards":                          labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer),
		"ignorE":                              labels.NewLabel("ignorE", "foo", labels.LabelSourceContainer),
		"ignore":                              labels.NewLabel("ignore", "foo", labels.LabelSourceContainer),
		"host":                                labels.NewLabel("host", "", labels.LabelSourceReserved),
		"io.kubernetes.pod.namespace":         labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceContainer),
		"ioXkubernetes":                       labels.NewLabel("ioXkubernetes", "foo", labels.LabelSourceContainer),
		"io.cilium.k8s.policy.cluster":        labels.NewLabel("io.cilium.k8s.policy.cluster", "default", labels.LabelSourceContainer),
		"io.cilium.k8s.policy.serviceaccount": labels.NewLabel("io.cilium.k8s.policy.serviceaccount", "luke", labels.LabelSourceContainer),
	}

	err := ParseLabelPrefixCfg(logger, []string{}, []string{}, "")
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
		"io.cilium.k8s.policy.serviceaccount":                       "luke",
	}
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceContainer)
	allLabels["host"] = labels.NewLabel("host", "", labels.LabelSourceReserved)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, len(wanted)-2) // -2 because we add two labels in the next lines
	allLabels["id.lizards"] = labels.NewLabel("id.lizards", "web", labels.LabelSourceContainer)
	allLabels["id.lizards.k8s"] = labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Equal(t, wanted, filtered)
}

func TestFilterLabelsDocExample(t *testing.T) {
	logger := hivetest.Logger(t)
	wanted := labels.Labels{

		"io.cilium.k8s.namespace.labels":      labels.NewLabel("io.cilium.k8s.namespace.labels", "foo", labels.LabelSourceK8s),
		"k8s-app-team":                        labels.NewLabel("k8s-app-team", "foo", labels.LabelSourceK8s),
		"app-production":                      labels.NewLabel("app-production", "foo", labels.LabelSourceK8s),
		"name-defined":                        labels.NewLabel("name-defined", "foo", labels.LabelSourceK8s),
		"kind":                                labels.NewLabel("kind", "foo", labels.LabelSourceK8s),
		"other":                               labels.NewLabel("other", "foo", labels.LabelSourceK8s),
		"host":                                labels.NewLabel("host", "", labels.LabelSourceReserved),
		"io.kubernetes.pod.namespace":         labels.NewLabel("io.kubernetes.pod.namespace", "docker", labels.LabelSourceK8s),
		"io.cilium.k8s.policy.cluster":        labels.NewLabel("io.cilium.k8s.policy.cluster", "default", labels.LabelSourceK8s),
		"io.cilium.k8s.policy.serviceaccount": labels.NewLabel("io.cilium.k8s.policy.serviceaccount", "luke", labels.LabelSourceK8s),
	}

	err := ParseLabelPrefixCfg(logger, []string{"k8s:io.kubernetes.pod.namespace", "k8s:k8s-app", "k8s:app", "k8s:name", "k8s:kind$", "k8s:other$"}, []string{}, "")
	require.NoError(t, err)
	dlpcfg := validLabelPrefixes
	allNormalLabels := map[string]string{
		"io.cilium.k8s.namespace.labels": "foo",
		"k8s-app-team":                   "foo",
		"app-production":                 "foo",
		"name-defined":                   "foo",
		"kind":                           "foo",
		"other":                          "foo",
	}
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceK8s)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 6)

	// Reserved labels are included.
	allLabels["host"] = labels.NewLabel("host", "", labels.LabelSourceReserved)
	filtered, _ = dlpcfg.filterLabels(allLabels)

	require.Len(t, filtered, 7)

	// io.kubernetes.pod.namespace=docker matches because the default list has k8s:io.kubernetes.pod.namespace.
	allLabels["io.kubernetes.pod.namespace"] = labels.NewLabel("io.kubernetes.pod.namespace", "docker", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)

	require.Len(t, filtered, 8)

	// io.cilium.k8s.policy.cluster=default matches because the default list has k8s:io.cilium.k8s.policy.cluster.
	allLabels["io.cilium.k8s.policy.cluster"] = labels.NewLabel("io.cilium.k8s.policy.cluster", "default", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 9)

	// io.cilium.k8s.policy.serviceaccount=default matches because the default list has k8s:io.cilium.k8s.policy.serviceaccount.
	allLabels["io.cilium.k8s.policy.serviceaccount"] = labels.NewLabel("io.cilium.k8s.policy.serviceaccount", "luke", labels.LabelSourceK8s)
	filtered, _ = dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, 10)
	// container:k8s-app-role=foo doesn't match because it doesn't have source k8s.
	allLabels["k8s-app-role"] = labels.NewLabel("k8s-app-role", "foo", labels.LabelSourceContainer)
	filtered, _ = dlpcfg.filterLabels(allLabels)

	require.Len(t, filtered, 10)
	require.Equal(t, wanted, filtered)
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

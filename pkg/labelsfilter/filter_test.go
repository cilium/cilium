// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilter

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

func TestFilterLabels(t *testing.T) {
	wanted := labels.Labels{
		"id.lizards":                          labels.NewLabel("id.lizards", "web", labels.LabelSourceK8s),
		"id.lizards.k8s":                      labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s),
		"io.kubernetes.pod.namespace":         labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceK8s),
		"app.kubernetes.io":                   labels.NewLabel("app.kubernetes.io", "my-nginx", labels.LabelSourceK8s),
		"foo2.lizards.k8s":                    labels.NewLabel("foo2.lizards.k8s", "web", labels.LabelSourceK8s),
		"io.cilium.k8s.policy.cluster":        labels.NewLabel("io.cilium.k8s.policy.cluster", "default", labels.LabelSourceK8s),
		"io.cilium.k8s.policy.serviceaccount": labels.NewLabel("io.cilium.k8s.policy.serviceaccount", "luke", labels.LabelSourceK8s),
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
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceK8s)
	filtered, _ := dlpcfg.filterLabels(allLabels)

	require.Len(t, filtered, 4)
	allLabels["id.lizards"] = labels.NewLabel("id.lizards", "web", labels.LabelSourceK8s)
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
		"app.kubernetes.io":                   labels.NewLabel("app.kubernetes.io", "my-nginx", labels.LabelSourceK8s),
		"id.lizards.k8s":                      labels.NewLabel("id.lizards.k8s", "web", labels.LabelSourceK8s),
		"id.lizards":                          labels.NewLabel("id.lizards", "web", labels.LabelSourceK8s),
		"ignorE":                              labels.NewLabel("ignorE", "foo", labels.LabelSourceK8s),
		"ignore":                              labels.NewLabel("ignore", "foo", labels.LabelSourceK8s),
		"host":                                labels.NewLabel("host", "", labels.LabelSourceReserved),
		"io.kubernetes.pod.namespace":         labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceK8s),
		"ioXkubernetes":                       labels.NewLabel("ioXkubernetes", "foo", labels.LabelSourceK8s),
		"io.cilium.k8s.policy.cluster":        labels.NewLabel("io.cilium.k8s.policy.cluster", "default", labels.LabelSourceK8s),
		"io.cilium.k8s.policy.serviceaccount": labels.NewLabel("io.cilium.k8s.policy.serviceaccount", "luke", labels.LabelSourceK8s),
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
		"topology.kubernetes.io/zone":                               "us-east-1-a",
		"topology.kubernetes.io/region":                             "us-east-1",
	}
	allLabels := labels.Map2Labels(allNormalLabels, labels.LabelSourceK8s)
	allLabels["host"] = labels.NewLabel("host", "", labels.LabelSourceReserved)
	filtered, _ := dlpcfg.filterLabels(allLabels)
	require.Len(t, filtered, len(wanted)-2) // -2 because we add two labels in the next lines
	allLabels["id.lizards"] = labels.NewLabel("id.lizards", "web", labels.LabelSourceK8s)
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
	// cni:k8s-app-role=foo doesn't match because it doesn't have source k8s.
	allLabels["k8s-app-role"] = labels.NewLabel("k8s-app-role", "foo", labels.LabelSourceCNI)
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
			got := FilterLabelsByRegex(tt.args.excludePatterns, tt.args.labels)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestParseLabelPrefixCfgReservedLabelWarning verifies that an error is
// logged when the user's configuration excludes (or fails to include) the
// reserved:host label. The test validates that:
//
//   - No error is logged when the reserved:host label will be included.
//   - An error is logged when the reserved:host label will be excluded.
func TestParseLabelPrefixCfgReservedLabelWarning(t *testing.T) {
	var (
		reservedHostLabel = labels.Label{Key: labels.IDNameHost, Value: "test", Source: labels.LabelSourceReserved}
		myLabel           = labels.Label{Key: "my-label", Value: "test", Source: labels.LabelSourceK8s}
		someLabel         = labels.Label{Key: "some-label", Value: "test", Source: labels.LabelSourceK8s}
	)

	tests := []struct {
		name            string
		parseLabelsFile string // JSON content of the label-prefix-file
		parseLabelsFlag []string
		filterLabels    labels.Labels
		wantIdentity    labels.Labels
		wantErrorLog    bool
	}{
		{
			name:            "file includes label",
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"k8s","prefix":"my-label","invert":false}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(myLabel),
			wantErrorLog:    true,
		},
		{
			name:            "file excludes label",
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"k8s","prefix":"my-label","invert":true}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(reservedHostLabel, someLabel),
			wantErrorLog:    false,
		},
		{
			name:            "file includes reserved host label",
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"reserved","prefix":"host","invert":false}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(reservedHostLabel),
			wantErrorLog:    false,
		},
		{
			name:            "file includes reserved host label by prefix",
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"reserved","prefix":"ho","invert":false}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(reservedHostLabel),
			wantErrorLog:    false,
		},
		{ // Label prefixes from v1 files are not treated as patterns. See https://github.com/cilium/cilium/issues/47918
			name:            "file fails to include reserved host label by pattern",
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"reserved","prefix":".*","invert":false}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantErrorLog:    true,
		},
		{
			name:            "file excludes reserved host label",
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"reserved","prefix":"host","invert":true}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(myLabel, someLabel),
			wantErrorLog:    true,
		},
		{
			name:            "file excludes reserved host label by prefix",
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"reserved","prefix":"ho","invert":true}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(myLabel, someLabel),
			wantErrorLog:    true,
		},
		{ // Label prefixes from v1 files are not treated as patterns. See https://github.com/cilium/cilium/issues/47918
			name:            "file fails to exclude reserved host label by pattern",
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"reserved","prefix":".*","invert":true}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantErrorLog:    false,
		},
		{
			name:            "flag includes label",
			parseLabelsFlag: []string{"k8s:my-label"},
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(myLabel, reservedHostLabel),
			wantErrorLog:    false,
		},
		{
			name:            "flag includes label prefix",
			parseLabelsFlag: []string{"k8s:my-"},
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(myLabel, reservedHostLabel),
			wantErrorLog:    false,
		},
		{
			name:            "flag includes label pattern",
			parseLabelsFlag: []string{"k8s:my-.*label"},
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(myLabel, reservedHostLabel),
			wantErrorLog:    false,
		},
		{
			name:            "flag excludes label",
			parseLabelsFlag: []string{"k8s:!my-label"},
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(reservedHostLabel, someLabel),
			wantErrorLog:    false,
		},
		{
			name:            "flag excludes label prefix",
			parseLabelsFlag: []string{"k8s:!my-"},
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(reservedHostLabel, someLabel),
			wantErrorLog:    false,
		},
		{
			name:            "flag excludes label pattern",
			parseLabelsFlag: []string{"k8s:!my-.*label"},
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(reservedHostLabel, someLabel),
			wantErrorLog:    false,
		},
		{
			name:            "flag includes reserved label pattern",
			parseLabelsFlag: []string{"reserved:.*"},
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(reservedHostLabel),
			wantErrorLog:    false,
		},
		{
			name:            "flag excludes reserved label pattern",
			parseLabelsFlag: []string{"reserved:!.*"},
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(myLabel, someLabel),
			wantErrorLog:    true,
		},
		{
			name:            "file includes label prefix, flag includes label prefix",
			parseLabelsFlag: []string{"k8s:my-other-label"},
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"k8s","prefix":"my-label","invert":false}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantIdentity:    labels.FromSlice(myLabel),
			wantErrorLog:    true,
		},
		{
			name:            "file excludes label prefix, flag includes label prefix",
			parseLabelsFlag: []string{"k8s:my-other-label"},
			parseLabelsFile: `{"version":1,"valid-prefixes":[{"source":"k8s","prefix":"my-label","invert":true}]}`,
			filterLabels:    labels.FromSlice(reservedHostLabel, myLabel, someLabel),
			wantErrorLog:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer

			handler := slog.NewTextHandler(&logs, &slog.HandlerOptions{
				Level: slog.LevelError,
			})
			logger := slog.New(handler)
			labelPrefixFile := createLabelPrefixFile(t, tt.parseLabelsFile)

			// Run ParseLabelPrefixCfg() so we can check the log output.
			gotErr := ParseLabelPrefixCfg(logger, tt.parseLabelsFlag, nil, labelPrefixFile)
			if gotErr != nil {
				t.Errorf("ParseLabelPrefixCfg() failed: %v", gotErr)

				return
			}

			// Check the log output.
			if tt.wantErrorLog {
				assert.Contains(t, logs.String(), reservedLabelsMissing)
			} else {
				assert.NotContains(t, logs.String(), reservedLabelsMissing)
			}

			// Run Filter() to confirm whether reserved:host is or is not
			// considered an identity label with the given config and labels.
			gotIdentityLabels, _ := Filter(tt.filterLabels)
			if diff := cmp.Diff(tt.wantIdentity.ToSlice(), gotIdentityLabels.ToSlice(), cmp.AllowUnexported(labels.Label{})); diff != "" {
				t.Errorf("identity labels mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// createLabelPrefixFile creates a temporary file containing the provided
// JSON label prefix configuration and returns its path. If the content is
// empty, it returns an empty string.
func createLabelPrefixFile(t *testing.T, parseLabelFileContent string) string {
	t.Helper()

	if parseLabelFileContent == "" {
		return ""
	}

	path := filepath.Join(t.TempDir(), "label-prefix.json")
	err := os.WriteFile(path, []byte(parseLabelFileContent), 0o600)
	require.NoError(t, err)

	return path
}

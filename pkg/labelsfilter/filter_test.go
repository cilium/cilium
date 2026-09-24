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

func TestFilterLabelsFromFile(t *testing.T) {
	var logs bytes.Buffer
	handler := slog.NewTextHandler(&logs, &slog.HandlerOptions{
		Level: slog.LevelError,
	})
	logger := slog.New(handler)

	// Mix of inclusive and exclusive label prefixes => whitelist==true.
	jsonContent := `{
        "version": 1,
        "valid-prefixes": [
            {"source": "k8s", "prefix": "controller-revision-hash", "invert": true},
            {"source": "k8s", "prefix": "pod-template-generation", "invert": true},
            {"source": "k8s", "prefix": "my-label", "invert": false}
        ]
    }`

	tmpDir := t.TempDir()
	tmpFile, err := os.Create(filepath.Join(tmpDir, "label-prefix.json"))
	require.NoError(t, err)
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(jsonContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	err = ParseLabelPrefixCfg(logger, []string{}, []string{}, tmpFile.Name())
	require.NoError(t, err)

	allLabels := labels.Map2Labels(map[string]string{
		"controller-revision-hash": "test",
		"pod-template-generation":  "test",
		"my-label":                 "test",
		"some-random-label":        "test",
	}, labels.LabelSourceK8s)
	reservedLabels := labels.Map2Labels(map[string]string{
		"host": "test",
	}, labels.LabelSourceReserved)
	allLabels.MergeLabels(reservedLabels)

	identityLabels, infoLabels := Filter(allLabels)

	// Verify reserved:host is NOT an identity label.
	assert.NotContains(t, identityLabels, "host")
	assert.Contains(t, infoLabels, "host")

	// Verify warning was logged about 'reserved:.*' labels not being considered for identity.
	assert.Contains(t, logs.String(), reservedLabelsPattern)

	// Verify inclusions were applied correctly to k8s labels.
	assert.Contains(t, identityLabels, "my-label")

	// Verify exclusions were applied correctly to k8s labels.
	assert.NotContains(t, identityLabels, "controller-revision-hash")
	assert.NotContains(t, identityLabels, "pod-template-generation")
	assert.Contains(t, infoLabels, "controller-revision-hash")
	assert.Contains(t, infoLabels, "pod-template-generation")

	// Verify other labels are not treated as identities (whitelist is on).
	assert.NotContains(t, identityLabels, "some-random-label")
	assert.Contains(t, infoLabels, "some-random-label")
}

func TestExclusiveOnlyFilterLabelsFromFile(t *testing.T) {
	var logs bytes.Buffer
	handler := slog.NewTextHandler(&logs, &slog.HandlerOptions{
		Level: slog.LevelError,
	})
	logger := slog.New(handler)

	// Only exclusive label prefixes => whitelist==false.
	jsonContent := `{
        "version": 1,
        "valid-prefixes": [
            {"source": "k8s", "prefix": "controller-revision-hash", "invert": true},
            {"source": "k8s", "prefix": "pod-template-generation", "invert": true}
        ]
    }`

	tmpDir := t.TempDir()
	tmpFile, err := os.Create(filepath.Join(tmpDir, "label-prefix.json"))
	require.NoError(t, err)
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(jsonContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	err = ParseLabelPrefixCfg(logger, []string{}, []string{}, tmpFile.Name())
	require.NoError(t, err)

	allLabels := labels.Map2Labels(map[string]string{
		"controller-revision-hash": "test",
		"pod-template-generation":  "test",
		"some-random-label":        "test",
	}, labels.LabelSourceK8s)
	reservedLabels := labels.Map2Labels(map[string]string{
		"host": "test",
	}, labels.LabelSourceReserved)
	allLabels.MergeLabels(reservedLabels)

	identityLabels, infoLabels := Filter(allLabels)

	// Verify reserved:host IS an identity label.
	assert.Contains(t, identityLabels, "host")
	assert.NotContains(t, infoLabels, "host")

	// Verify NO warning was logged about 'reserved:.*' labels not being considered for identity.
	assert.NotContains(t, logs.String(), reservedLabelsPattern)

	// Verify exclusions were applied correctly to k8s labels.
	assert.NotContains(t, identityLabels, "controller-revision-hash")
	assert.NotContains(t, identityLabels, "pod-template-generation")
	assert.Contains(t, infoLabels, "controller-revision-hash")
	assert.Contains(t, infoLabels, "pod-template-generation")

	// Verify other labels are still treated as identities (whitelist is off).
	assert.Contains(t, identityLabels, "some-random-label")
}

func TestFilterLabelsFromFileWithInclusiveFlag(t *testing.T) {
	var logs bytes.Buffer
	handler := slog.NewTextHandler(&logs, &slog.HandlerOptions{
		Level: slog.LevelError,
	})
	logger := slog.New(handler)

	// File contains only exclusive rules, so whitelist would be false from
	// the file alone.
	jsonContent := `{
        "version": 1,
        "valid-prefixes": [
            {"source": "k8s", "prefix": "pod-template-generation", "invert": true}
        ]
    }`

	tmpDir := t.TempDir()
	tmpFile, err := os.Create(filepath.Join(tmpDir, "label-prefix.json"))
	require.NoError(t, err)
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(jsonContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	// Passing an inclusive --labels flag flips cfg.whitelist to true.
	err = ParseLabelPrefixCfg(logger, []string{"my-label"}, []string{}, tmpFile.Name())
	require.NoError(t, err)

	allLabels := labels.Map2Labels(map[string]string{
		"pod-template-generation": "test",
		"my-label":                "test",
		"some-random-label":       "test",
	}, labels.LabelSourceK8s)
	reservedLabels := labels.Map2Labels(map[string]string{
		"host": "test",
	}, labels.LabelSourceReserved)
	allLabels.MergeLabels(reservedLabels)

	identityLabels, infoLabels := Filter(allLabels)

	// The inclusive flag set whitelist=true, but reserved:.* is not included
	// in the final label list, so the error must be logged.
	assert.Contains(t, logs.String(), reservedLabelsPattern)

	// Reserved labels are not identity labels (whitelist is true).
	assert.NotContains(t, identityLabels, "host")
	assert.Contains(t, infoLabels, "host")

	// The inclusive label is an identity label.
	assert.Contains(t, identityLabels, "my-label")

	// File exclusions still apply.
	assert.NotContains(t, identityLabels, "pod-template-generation")
	assert.Contains(t, infoLabels, "pod-template-generation")

	// Other labels are not identity labels (whitelist is true).
	assert.NotContains(t, identityLabels, "some-random-label")
	assert.Contains(t, infoLabels, "some-random-label")
}

func TestFilterLabelsReservedExplicitlyExcluded(t *testing.T) {
	var logs bytes.Buffer
	handler := slog.NewTextHandler(&logs, &slog.HandlerOptions{
		Level: slog.LevelError,
	})
	logger := slog.New(handler)

	// File contains only exclusive rules, so whitelist would be false from
	// the file alone.
	jsonContent := `{
        "version": 1,
        "valid-prefixes": [
            {"source": "k8s", "prefix": "controller-revision-hash", "invert": true}
        ]
    }`

	tmpDir := t.TempDir()
	tmpFile, err := os.Create(filepath.Join(tmpDir, "label-prefix.json"))
	require.NoError(t, err)
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(jsonContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	// User explicitly excludes all reserved labels via --labels, so whitelist
	// stays false.
	err = ParseLabelPrefixCfg(logger, []string{"reserved:!.*"}, []string{}, tmpFile.Name())
	require.NoError(t, err)

	allLabels := labels.Map2Labels(map[string]string{
		"controller-revision-hash": "test",
		"some-random-label":        "test",
	}, labels.LabelSourceK8s)
	reservedLabels := labels.Map2Labels(map[string]string{
		"host": "test",
	}, labels.LabelSourceReserved)
	allLabels.MergeLabels(reservedLabels)

	identityLabels, infoLabels := Filter(allLabels)

	// Reserved labels are explicitly excluded, so the error must be logged.
	assert.Contains(t, logs.String(), reservedLabelsPattern)

	// Reserved label is not an identity label.
	assert.NotContains(t, identityLabels, "host")
	assert.Contains(t, infoLabels, "host")

	// File exclusion still applies.
	assert.NotContains(t, identityLabels, "controller-revision-hash")
	assert.Contains(t, infoLabels, "controller-revision-hash")

	// Other labels are still identity labels (whitelist is false).
	assert.Contains(t, identityLabels, "some-random-label")
}

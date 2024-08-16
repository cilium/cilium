// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium
// Copyright The Helm Authors.

package helm

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cilium/cilium-cli/internal/utils"

	semver2 "github.com/blang/semver/v4"
	helm "github.com/cilium/charts"
	"github.com/cilium/cilium/pkg/versioncheck"
	"golang.org/x/mod/semver"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/releaseutil"
	"helm.sh/helm/v3/pkg/strvals"
	corev1 "k8s.io/api/core/v1"
)

var settings = cli.New()

// State contains Helm state for the current Cilium installation. Cilium CLI retrieves this
// information from cilium-cli-helm-values Kubernetes secret.
type State struct {
	// Pointer to cilium-cli-helm-values secret.
	Secret *corev1.Secret
	// Helm chart version.
	Version semver2.Version
	// Helm values used for this installation.
	Values chartutil.Values
}

// filterManifests a map of generated manifests. The Key is the filename and the
// Value is its manifest.
func filterManifests(manifest string) map[string]string {
	// This is necessary to ensure consistent manifest ordering when using --show-only
	// with globs or directory names.
	var manifests bytes.Buffer
	fmt.Fprintln(&manifests, strings.TrimSpace(manifest))

	splitManifests := releaseutil.SplitManifests(manifests.String())
	manifestsKeys := make([]string, 0, len(splitManifests))
	for k := range splitManifests {
		manifestsKeys = append(manifestsKeys, k)
	}
	sort.Sort(releaseutil.BySplitManifestsOrder(manifestsKeys))

	manifestNameRegex := regexp.MustCompile("# Source: [^/]+/(.+)")

	var (
		manifestsToRender = map[string]string{}
	)

	for _, manifestKey := range manifestsKeys {
		manifest := splitManifests[manifestKey]
		submatch := manifestNameRegex.FindStringSubmatch(manifest)
		if len(submatch) == 0 {
			continue
		}
		manifestName := submatch[1]
		// manifest.Name is rendered using linux-style filepath separators on Windows as
		// well as macOS/linux.
		manifestPathSplit := strings.Split(manifestName, "/")
		// manifest.Path is connected using linux-style filepath separators on Windows as
		// well as macOS/linux
		manifestPath := strings.Join(manifestPathSplit, "/")

		manifestsToRender[manifestPath] = manifest
	}
	return manifestsToRender
}

func mergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					out[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}

func valuesToString(prevKey string, b map[string]interface{}) string {
	var out []string
	for k, v := range b {
		switch v := v.(type) {
		case chartutil.Values:
			if prevKey != "" {
				out = append(out, valuesToString(fmt.Sprintf("%s.%s", prevKey, k), v))
			} else {
				out = append(out, valuesToString(k, v))
			}
			continue
		case map[string]interface{}:
			if prevKey != "" {
				out = append(out, valuesToString(fmt.Sprintf("%s.%s", prevKey, k), v))
			} else {
				out = append(out, valuesToString(k, v))
			}
			continue
		case []interface{}:
			if prevKey != "" {
				out = append(out, sliceValuesToString(fmt.Sprintf("%s.%s", prevKey, k), v))
			} else {
				out = append(out, sliceValuesToString(k, v))
			}
			continue
		}
		if prevKey != "" {
			if strings.Contains(k, ".") {
				k = strings.ReplaceAll(k, ".", `\\.`)
			}
			out = append(out, fmt.Sprintf("%s.%s=%v", prevKey, k, v))
		} else {
			out = append(out, fmt.Sprintf("%s=%v", k, v))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func sliceValuesToString(prevKey string, b []interface{}) string {
	var out []string
	for i, v := range b {
		switch v := v.(type) {
		case chartutil.Values:
			out = append(out, valuesToString(fmt.Sprintf("%s[%d]", prevKey, i), v))
			continue
		case map[string]interface{}:
			out = append(out, valuesToString(fmt.Sprintf("%s[%d]", prevKey, i), v))
			continue
		case []interface{}:
			out = append(out, sliceValuesToString(fmt.Sprintf("%s[%d]", prevKey, i), v))
			continue
		case string:
			out = append(out, fmt.Sprintf("%s[%d]=%s", prevKey, i, v))
			continue
		case int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64:
			out = append(out, fmt.Sprintf("%s[%d]=%d", prevKey, i, v))
			continue
		case float32, float64:
			out = append(out, fmt.Sprintf("%s[%d]=%f", prevKey, i, v))
			continue
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func newClient(namespace, k8sVersion string) (*action.Install, error) {
	actionConfig := new(action.Configuration)
	helmClient := action.NewInstall(actionConfig)
	helmClient.DryRun = true
	helmClient.ReleaseName = "release-name"
	helmClient.Replace = true // Skip the name check
	helmClient.ClientOnly = true
	helmClient.APIVersions = []string{k8sVersion}
	helmClient.Namespace = namespace

	return helmClient, nil
}

func newChartFromCiliumVersion(ciliumVersion semver2.Version) (*chart.Chart, error) {
	helmTgz, err := helm.HelmFS.ReadFile(fmt.Sprintf("cilium-%s.tgz", ciliumVersion))
	if err != nil {
		return nil, fmt.Errorf("cilium version not found: %s", err)
	}

	// Check chart dependencies to make sure all are present in /charts
	return loader.LoadArchive(bytes.NewReader(helmTgz))
}

func newChartFromDirectory(directory string) (*chart.Chart, error) {
	return loader.LoadDir(directory)
}

// GenManifests returns the generated manifests in a map that maps the manifest
// name to its contents.
func GenManifests(
	ctx context.Context,
	helmChartDirectory, k8sVersion string,
	ciliumVer semver2.Version,
	namespace string,
	helmValues map[string]interface{},
) (map[string]string, error) {
	var (
		helmChart *chart.Chart
		err       error
	)
	if helmDir := helmChartDirectory; helmDir != "" {
		helmChart, err = newChartFromDirectory(helmDir)
		if err != nil {
			return nil, err
		}
	} else {
		helmChart, err = newChartFromCiliumVersion(ciliumVer)
		if err != nil {
			return nil, err
		}
	}

	helmClient, err := newClient(namespace, k8sVersion)
	if err != nil {
		return nil, err
	}

	rel, err := helmClient.RunWithContext(ctx, helmChart, helmValues)
	if err != nil {
		return nil, err
	}

	return filterManifests(rel.Manifest), nil
}

// MergeVals merges all values from flag options ('helmFlagOpts'),
// auto-generated helm options based on environment ('helmMapOpts'),
// helm values from a previous installation ('helmValues'),
// extra options that are not defined as helm flags ('extraConfigMapOpts')
// and returns a single map with all of these options merged.
// It will log a message so that users can replicate the same behavior as the
// CLI. The log message will be slightly different depending on if
// 'helmChartDirectory' is set or not.
// Both 'helmMapOpts', 'helmValues', 'extraConfigMapOpts' can be nil.
func MergeVals(
	logger utils.Logger,
	printHelmTemplate bool,
	helmFlagOpts values.Options,
	helmMapOpts map[string]string,
	helmValues,
	extraConfigMapOpts chartutil.Values,
	helmChartDirectory string,
	ciliumVer semver2.Version,
	namespace string,
) (map[string]interface{}, error) {

	// Create helm values from helmMapOpts
	var helmOpts []string
	for k, v := range helmMapOpts {
		helmOpts = append(helmOpts, fmt.Sprintf("%s=%s", k, v))
	}

	helmOptsStr := strings.Join(helmOpts, ",")

	if helmValues == nil {
		helmValues = map[string]interface{}{}
	}
	err := strvals.ParseInto(helmOptsStr, helmValues)
	if err != nil {
		return nil, fmt.Errorf("error parsing helm options %q: %w", helmOptsStr, err)
	}

	// Get the user-defined helm options passed by flag
	p := getter.All(settings)
	userVals, err := helmFlagOpts.MergeValues(p)
	if err != nil {
		return nil, err
	}

	// User-defined helm options will overwrite the default cilium-cli helm options
	userVals = mergeMaps(helmValues, userVals)

	// Merge the user-defined helm options into the `--config` map. This
	// effectively means that any --helm-set=extraConfig.<key> will overwrite
	// the values of --config <key>
	extraConfig := map[string]interface{}{}
	if len(extraConfigMapOpts) != 0 {
		extraConfig["extraConfig"] = extraConfigMapOpts
	}

	vals := mergeMaps(extraConfig, userVals)

	valsStr := valuesToString("", vals)

	if printHelmTemplate {
		if helmChartDirectory != "" {
			logger.Log("ℹ️  helm template --namespace %s cilium %q --version %s --set %s", namespace, helmChartDirectory, ciliumVer, valsStr)
		} else {
			logger.Log("ℹ️  helm template --namespace %s cilium cilium/cilium --version %s --set %s", namespace, ciliumVer, valsStr)
		}
	}

	return vals, nil
}

// ListVersions returns a list of available Helm chart versions (with "v" prefix) sorted by semver in ascending order.
func ListVersions() ([]string, error) {
	var versions []string
	re := regexp.MustCompile(`^cilium-(.+)\.tgz$`)
	entries, err := helm.HelmFS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		match := re.FindStringSubmatch(entry.Name())
		if len(match) == 2 {
			// semver.Sort expects a leading "v" in version strings.
			versions = append(versions, "v"+match[1])
		}
	}
	semver.Sort(versions)
	return versions, nil
}

// ResolveHelmChartVersion resolves Helm chart version based on --version and --chart-directory flags.
func ResolveHelmChartVersion(versionFlag, chartDirectoryFlag string) (semver2.Version, error) {
	if chartDirectoryFlag == "" {
		// If --chart-directory flag is not specified, use the version specified with --version flag.
		version, err := utils.ParseCiliumVersion(versionFlag)
		if err != nil {
			return semver2.Version{}, err
		}
		if _, err = newChartFromCiliumVersion(version); err != nil {
			return semver2.Version{}, err
		}
		return version, nil
	}

	// Get the chart version from the local Helm chart specified with --chart-directory flag.
	localChart, err := newChartFromDirectory(chartDirectoryFlag)
	if err != nil {
		return semver2.Version{}, fmt.Errorf("failed to load Helm chart directory %s: %s", chartDirectoryFlag, err)
	}
	return versioncheck.MustVersion(localChart.Metadata.Version), nil
}

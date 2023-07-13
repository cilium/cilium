// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
// Copyright The Helm Authors.

package helm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
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
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/releaseutil"
	"helm.sh/helm/v3/pkg/strvals"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
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

		if existing, ok := manifestsToRender[manifestPath]; ok {
			manifestsToRender[manifestPath] = existing + "\n---\n" + manifest
		} else {
			manifestsToRender[manifestPath] = manifest
		}
	}
	return manifestsToRender
}

// Merge maps recursively merges the values of b into a copy of a, preferring the values from b
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

func newClient(namespace string, k8sVersion string, apiVersions []string) (*action.Install, error) {
	actionConfig := new(action.Configuration)
	helmClient := action.NewInstall(actionConfig)
	helmClient.DryRun = true
	helmClient.ReleaseName = "release-name"
	helmClient.Replace = true // Skip the name check
	helmClient.ClientOnly = true
	helmClient.Namespace = namespace
	if len(apiVersions) == 0 {
		helmClient.APIVersions = []string{k8sVersion}
	} else {
		helmClient.APIVersions = apiVersions
	}

	return helmClient, nil
}

func newChartFromEmbeddedFile(ciliumVersion semver2.Version) (*chart.Chart, error) {
	helmTgz, err := helm.HelmFS.ReadFile(fmt.Sprintf("cilium-%s.tgz", ciliumVersion))
	if err != nil {
		return nil, fmt.Errorf("cilium version not found: %w", err)
	}

	// Check chart dependencies to make sure all are present in /charts
	return loader.LoadArchive(bytes.NewReader(helmTgz))
}

func newChartFromDirectory(directory string) (*chart.Chart, error) {
	return loader.LoadDir(directory)
}

// newChartFromRemoteWithCache fetches the chart from remote repository, the chart file
// is then stored in the local cache directory for future usage.
func newChartFromRemoteWithCache(ciliumVersion semver2.Version, repository string) (*chart.Chart, error) {
	cacheDir, err := ciliumCacheDir()
	if err != nil {
		return nil, err
	}

	file := path.Join(cacheDir, fmt.Sprintf("cilium-%s.tgz", ciliumVersion))
	if _, err = os.Stat(file); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}

		// Download the chart from remote repository
		actionConfig := new(action.Configuration)
		pull := action.NewPullWithOpts(action.WithConfig(actionConfig))
		pull.Settings = settings
		pull.Version = ciliumVersion.String()
		pull.DestDir = cacheDir
		chartRef := "cilium"
		if registry.IsOCI(repository) {
			// For OCI repositories, Pull action expects the full repository name as the
			// chartRef argument, and RepoURL must be kept unspecified.
			chartRef = repository
			// OCI repos need RegistryClient for some reason. Set it here.
			registryClient, err := registry.NewClient()
			if err != nil {
				return nil, err
			}
			actionConfig.RegistryClient = registryClient
		} else {
			pull.RepoURL = repository
		}
		if _, err = pull.Run(chartRef); err != nil {
			return nil, err
		}
	}

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return loader.LoadArchive(f)
}

func ciliumCacheDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	res := path.Join(cacheDir, "cilium-cli")
	err = os.MkdirAll(res, 0755)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return res, nil
}

// GenManifests returns the generated manifests in a map that maps the manifest
// name to its contents.
func GenManifests(
	ctx context.Context,
	helmChartDirectory, k8sVersion string,
	ciliumVer semver2.Version,
	namespace string,
	helmValues map[string]interface{},
	apiVersions []string,
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
		helmChart, err = newChartFromEmbeddedFile(ciliumVer)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
			// Helm repository is not configurable in the classic mode. Always use the default Helm repository.
			helmChart, err = newChartFromRemoteWithCache(ciliumVer, defaults.HelmRepository)
			if err != nil {
				return nil, err
			}
		}
	}

	helmClient, err := newClient(namespace, k8sVersion, apiVersions)
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
// Both 'helmMapOpts', 'helmValues', 'extraConfigMapOpts', can be nil.
func MergeVals(
	helmFlagOpts values.Options,
	helmMapOpts map[string]string,
	helmValues,
	extraConfigMapOpts chartutil.Values,
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

	return vals, nil
}

// ParseVals takes a slice of Helm values of the form
// ["some.chart.value=val1", "some.other.value=val2"]
// and returns a deeply nested map of Values of the form
// expected by Helm actions.
func ParseVals(helmStrValues []string) (map[string]interface{}, error) {
	helmValStr := strings.Join(helmStrValues, ",")
	helmValues := map[string]interface{}{}
	err := strvals.ParseInto(helmValStr, helmValues)
	if err != nil {
		return nil, fmt.Errorf("error parsing helm options %q: %w", helmValStr, err)
	}
	return helmValues, nil
}

// PrintHelmTemplateCommand will log a message so that users can replicate
// the same behavior as the CLI. The log message will be slightly different
// depending on if 'helmChartDirectory' is set or not.
// If 'apiVersions' is given, said values will be added to the log message.
func PrintHelmTemplateCommand(
	logger utils.Logger,
	helmValues map[string]any,
	helmChartDirectory string,
	namespace string,
	ciliumVer semver2.Version,
	apiVersions []string,
) {
	valsStr := valuesToString("", helmValues)
	apiVersionsStr := ""
	if len(apiVersions) > 0 {
		for _, av := range apiVersions {
			apiVersionsStr = fmt.Sprintf("%s --api-versions %s", apiVersionsStr, av)
		}
	}
	if helmChartDirectory != "" {
		logger.Log("ℹ️  helm template --namespace %s cilium %q --version %s --set %s%s", namespace, helmChartDirectory, ciliumVer, valsStr, apiVersionsStr)
	} else {
		logger.Log("ℹ️  helm template --namespace %s cilium cilium/cilium --version %s --set %s%s", namespace, ciliumVer, valsStr, apiVersionsStr)
	}
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

// ResolveHelmChartVersion resolves Helm chart version based on --version, --chart-directory, and --repository flags.
func ResolveHelmChartVersion(versionFlag, chartDirectoryFlag, repository string) (semver2.Version, *chart.Chart, error) {
	// If repository is empty, set it to the default Helm repository ("https://helm.cilium.io") for backward compatibility.
	if repository == "" {
		repository = defaults.HelmRepository
	}
	if chartDirectoryFlag == "" {
		// If --chart-directory flag is not specified, use the version specified with --version flag.
		return resolveChartVersion(versionFlag, repository)
	}

	// Get the chart version from the local Helm chart specified with --chart-directory flag.
	localChart, err := newChartFromDirectory(chartDirectoryFlag)
	if err != nil {
		return semver2.Version{}, nil, fmt.Errorf("failed to load Helm chart directory %s: %s", chartDirectoryFlag, err)
	}
	return versioncheck.MustVersion(localChart.Metadata.Version), localChart, nil
}

func resolveChartVersion(versionFlag string, repository string) (semver2.Version, *chart.Chart, error) {
	version, err := utils.ParseCiliumVersion(versionFlag)
	if err != nil {
		return semver2.Version{}, nil, err
	}

	// If the repository is the default repository ("https://helm.cilium.io"), check embedded charts first.
	if repository == defaults.HelmRepository {
		helmChart, err := newChartFromEmbeddedFile(version)
		if err == nil {
			return version, helmChart, nil
		}

		if !errors.Is(err, fs.ErrNotExist) {
			return semver2.Version{}, nil, err
		}
	}

	helmChart, err := newChartFromRemoteWithCache(version, repository)
	if err != nil {
		return semver2.Version{}, nil, err
	}
	return version, helmChart, nil
}

// GetCurrentRelease gets the currently deployed release
func GetCurrentRelease(
	k8sClient genericclioptions.RESTClientGetter,
	namespace, name string,
) (*release.Release, error) {
	// Use the default Helm driver (Kubernetes secret).
	helmDriver := ""
	actionConfig := action.Configuration{}
	logger := func(format string, v ...interface{}) {}
	if err := actionConfig.Init(k8sClient, namespace, helmDriver, logger); err != nil {
		return nil, err
	}
	currentRelease, err := actionConfig.Releases.Last(name)
	if err != nil {
		return nil, err
	}
	return currentRelease, nil
}

// UpgradeParameters contains parameters for helm upgrade operation.
type UpgradeParameters struct {
	// Namespace in which the Helm release is installed.
	Namespace string
	// Name of the Helm release to upgrade.
	Name string
	// Chart is the Helm chart to use for the release
	Chart *chart.Chart
	// Helm values to pass during upgrade.
	Values map[string]interface{}
	// --reset-values flag from Helm upgrade. See https://helm.sh/docs/helm/helm_upgrade/ for details.
	ResetValues bool
	// --reuse-values flag from Helm upgrade. See https://helm.sh/docs/helm/helm_upgrade/ for details.
	ReuseValues bool
	// Wait determines if Helm actions will wait for completion
	Wait bool
	// WaitDuration is the timeout for helm operations
	WaitDuration time.Duration
	// DryRun writes resources to be installed to stdout without actually installing them. For Helm
	// installation mode only.
	DryRun bool
	// DryRunHelmValues writes non-default Helm values to stdout without performing the actual installation.
	// For Helm installation mode only.
	DryRunHelmValues bool
}

// Upgrade upgrades the existing Helm release with the given Helm chart and values
func Upgrade(
	ctx context.Context,
	actionConfig *action.Configuration,
	params UpgradeParameters,
) (*release.Release, error) {
	if params.Chart == nil {
		currentRelease, err := actionConfig.Releases.Last(params.Name)
		if err != nil {
			return nil, err
		}
		params.Chart = currentRelease.Chart
	}

	helmClient := action.NewUpgrade(actionConfig)
	helmClient.Namespace = params.Namespace
	helmClient.ResetValues = params.ResetValues
	helmClient.ReuseValues = params.ReuseValues
	helmClient.Wait = params.Wait
	helmClient.Timeout = params.WaitDuration
	helmClient.DryRun = params.DryRun || params.DryRunHelmValues

	return helmClient.RunWithContext(ctx, defaults.HelmReleaseName, params.Chart, params.Values)
}

// GetParameters contains parameters for helm get operation.
type GetParameters struct {
	// Namespace in which the Helm release is installed.
	Namespace string
	// Name of the Helm release to get.
	Name string
}

// Get returns the Helm release specified by GetParameters.
func Get(
	actionConfig *action.Configuration,
	params GetParameters,
) (*release.Release, error) {
	helmClient := action.NewGet(actionConfig)
	return helmClient.Run(params.Name)
}

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
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"

	"github.com/blang/semver/v4"
	helm "github.com/cilium/charts"
	"github.com/cilium/cilium/pkg/versioncheck"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/strvals"
)

var settings = cli.New()

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

func newChartFromEmbeddedFile(ciliumVersion semver.Version) (*chart.Chart, error) {
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
func newChartFromRemoteWithCache(ciliumVersion semver.Version, repository string) (*chart.Chart, error) {
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
	// effectively means that any --set=extraConfig.<key> will overwrite
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

// ListVersions returns a list of available Helm chart versions sorted by semver in ascending order.
func ListVersions() ([]semver.Version, error) {
	var versions []semver.Version
	re := regexp.MustCompile(`^cilium-(.+)\.tgz$`)
	entries, err := helm.HelmFS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		match := re.FindStringSubmatch(entry.Name())
		if len(match) == 2 {
			version, err := semver.Parse(match[1])
			if err != nil {
				// Ignore old charts that don't follow semver (v1.{6,7,8,9}-dev).
				continue
			}
			versions = append(versions, version)
		}
	}
	semver.Sort(versions)
	return versions, nil
}

// ResolveHelmChartVersion resolves Helm chart version based on --version, --chart-directory, and --repository flags.
func ResolveHelmChartVersion(versionFlag, chartDirectoryFlag, repository string) (semver.Version, *chart.Chart, error) {
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
		return semver.Version{}, nil, fmt.Errorf("failed to load Helm chart directory %s: %s", chartDirectoryFlag, err)
	}
	return versioncheck.MustVersion(localChart.Metadata.Version), localChart, nil
}

func resolveChartVersion(versionFlag string, repository string) (semver.Version, *chart.Chart, error) {
	version, err := utils.ParseCiliumVersion(versionFlag)
	if err != nil {
		return semver.Version{}, nil, err
	}

	// If the repository is the default repository ("https://helm.cilium.io"), check embedded charts first.
	if repository == defaults.HelmRepository {
		helmChart, err := newChartFromEmbeddedFile(version)
		if err == nil {
			return version, helmChart, nil
		}

		if !errors.Is(err, fs.ErrNotExist) {
			return semver.Version{}, nil, err
		}
	}

	helmChart, err := newChartFromRemoteWithCache(version, repository)
	if err != nil {
		return semver.Version{}, nil, err
	}
	return version, helmChart, nil
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

func (p *UpgradeParameters) IsDryRun() bool {
	return p.DryRun || p.DryRunHelmValues
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
	helmClient.DryRun = params.IsDryRun()

	return helmClient.RunWithContext(ctx, defaults.HelmReleaseName, params.Chart, params.Values)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/blang/semver/v4"
	"github.com/cilium/hive/cell"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/gateway-api/crds"
	"github.com/cilium/cilium/pkg/k8s/apis/crdhelpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	// crdManagedByLabel marks the Gateway API CRDs which are managed by the
	// Cilium Operator. CRDs without this label are considered as externally
	// managed (e.g. by Helm, Flux, Argo CD or kubectl) and are never
	// modified.
	crdManagedByLabel = "app.kubernetes.io/managed-by"
	crdManagedByValue = "cilium-operator"
)

type crdAction string

const (
	// crdActionUpToDate: the CRD is managed by Cilium and matches the
	// bundled version.
	crdActionUpToDate crdAction = "up-to-date"
	// crdActionUpgrade: the CRD is managed by Cilium and older than the
	// bundled version.
	crdActionUpgrade crdAction = "upgrade"
	// crdActionNewer: the CRD is managed by Cilium but newer than the bundled
	// version (e.g. after a Cilium downgrade). It is never downgraded.
	crdActionNewer crdAction = "newer"
	// crdActionExternal: the CRD is managed externally and compatible.
	crdActionExternal crdAction = "external"
	// crdActionConflict: the CRD cannot be managed by Cilium and is not
	// known to be compatible.
	crdActionConflict crdAction = "conflict"
)

type crdDecision struct {
	action crdAction
	reason string
}

func shouldInstallGatewayAPICRDs(operatorCfg *operatorOption.OperatorConfig, cfg gatewayApiConfig) bool {
	return operatorCfg.EnableGatewayAPI && cfg.GatewayAPIInstallCRDs
}

// crdInstallTimeout bounds the installation of the Gateway API CRDs,
// including waiting for them to be established.
const crdInstallTimeout = 2 * time.Minute

// installBundledCRDs installs the Gateway API CRDs embedded in Cilium.
func installBundledCRDs(logger *slog.Logger, clientset apiextensionsclient.Interface, health cell.Health) error {
	targets, err := bundledCRDs()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), crdInstallTimeout)
	defer cancel()

	return installCRDs(ctx, logger, clientset, health.NewScope("crd-install"), targets)
}

// bundledCRDs returns the Gateway API CRDs embedded in Cilium, labeled as
// managed by the Cilium Operator.
func bundledCRDs() ([]*apiextensionsv1.CustomResourceDefinition, error) {
	targets, err := crds.Standard()
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("no Gateway API CRDs bundled")
	}
	for _, crd := range targets {
		if _, err := bundleVersion(crd); err != nil {
			return nil, err
		}
		if crd.Labels == nil {
			crd.Labels = map[string]string{}
		}
		crd.Labels[crdManagedByLabel] = crdManagedByValue
	}
	return targets, nil
}

func bundleVersion(crd *apiextensionsv1.CustomResourceDefinition) (semver.Version, error) {
	v, ok := crd.Annotations[crds.BundleVersionAnnotation]
	if !ok {
		return semver.Version{}, fmt.Errorf("CRD %s has no %s annotation", crd.Name, crds.BundleVersionAnnotation)
	}
	ver, err := versioncheck.Version(v)
	if err != nil {
		return semver.Version{}, fmt.Errorf("CRD %s has an invalid %s annotation %q: %w", crd.Name, crds.BundleVersionAnnotation, v, err)
	}
	return ver, nil
}

// classifyCRD decides how to handle a Gateway API CRD already present in the
// cluster, given the bundled target CRD. It never returns a decision which
// would downgrade a CRD, switch its channel, or take over an externally
// managed CRD: these could drop fields or API versions, and hence delete the
// corresponding configuration from existing resources.
func classifyCRD(target, current *apiextensionsv1.CustomResourceDefinition) (crdDecision, error) {
	targetVersion, err := bundleVersion(target)
	if err != nil {
		return crdDecision{}, err
	}
	targetChannel := target.Annotations[crds.ChannelAnnotation]
	channel := current.Annotations[crds.ChannelAnnotation]
	currentVersion, versionErr := bundleVersion(current)
	managed := current.Labels[crdManagedByLabel] == crdManagedByValue

	if managed && channel == targetChannel {
		switch {
		case versionErr != nil:
			return crdDecision{crdActionUpgrade, versionErr.Error()}, nil
		case currentVersion.LT(targetVersion):
			return crdDecision{crdActionUpgrade, fmt.Sprintf("upgrading from %s to %s", current.Annotations[crds.BundleVersionAnnotation], target.Annotations[crds.BundleVersionAnnotation])}, nil
		case currentVersion.GT(targetVersion):
			return crdDecision{crdActionNewer, fmt.Sprintf("installed version %s is newer than bundled version %s, not downgrading", current.Annotations[crds.BundleVersionAnnotation], target.Annotations[crds.BundleVersionAnnotation])}, nil
		default:
			return crdDecision{crdActionUpToDate, ""}, nil
		}
	}

	// The CRD is not (or no longer) managed by Cilium.
	origin := "externally managed"
	if managed {
		origin = fmt.Sprintf("labeled as managed by %s but on channel %q, not managing it", crdManagedByValue, channel)
	}
	switch {
	case versionErr != nil:
		return crdDecision{crdActionConflict, fmt.Sprintf("%s, unknown version: %s", origin, versionErr)}, nil
	case currentVersion.LT(targetVersion):
		return crdDecision{crdActionConflict, fmt.Sprintf("%s, channel %q version %s is older than the required version %s", origin, channel, current.Annotations[crds.BundleVersionAnnotation], target.Annotations[crds.BundleVersionAnnotation])}, nil
	default:
		return crdDecision{crdActionExternal, fmt.Sprintf("%s, channel %q version %s", origin, channel, current.Annotations[crds.BundleVersionAnnotation])}, nil
	}
}

// installCRDs creates the missing Gateway API CRDs and upgrades the ones
// managed by Cilium. CRDs are never deleted. It is idempotent: CRDs which are
// up-to-date are not written.
//
// Conflicts are reported through logs and the module health but do not fail
// the operator, as Gateway API support doesn't depend on the CRDs being
// managed by Cilium. Other errors are returned, so that the operator restarts
// and retries, as for the Cilium CRDs.
func installCRDs(
	ctx context.Context,
	logger *slog.Logger,
	clientset apiextensionsclient.Interface,
	health cell.Health,
	targets []*apiextensionsv1.CustomResourceDefinition,
) error {
	var conflicts error
	for _, target := range targets {
		scopedLog := logger.With(logfields.CRDName, target.Name)

		var decision crdDecision
		_, err := crdhelpers.CreateUpdateCRD(ctx, logger, clientset, target, crdhelpers.NewDefaultPoller(),
			func(target, current *apiextensionsv1.CustomResourceDefinition) (bool, error) {
				var err error
				decision, err = classifyCRD(target, current)
				return decision.action == crdActionUpgrade, err
			},
		)
		switch {
		case k8serrors.IsInvalid(err):
			// The apiserver refused the upgrade of a CRD managed by Cilium,
			// e.g. as it'd remove a version still listed in status.storedVersions.
			conflicts = errors.Join(conflicts, fmt.Errorf("%s: upgrade rejected by the API server: %w", target.Name, err))
			continue
		case err != nil:
			health.Degraded("Failed to install Gateway API CRDs", err)
			return fmt.Errorf("unable to install Gateway API CRD %s: %w", target.Name, err)
		}

		switch decision.action {
		case crdActionConflict:
			conflicts = errors.Join(conflicts, fmt.Errorf("%s: %s", target.Name, decision.reason))
		case crdActionNewer, crdActionExternal:
			scopedLog.Info("Not modifying Gateway API CRD", logfields.Reason, decision.reason)
		case crdActionUpgrade:
			scopedLog.Info("Upgraded Gateway API CRD", logfields.Reason, decision.reason)
		}
	}

	if conflicts != nil {
		logger.Error(
			"Some Gateway API CRDs are incompatible with this version of Cilium and could not be installed or upgraded. "+
				"Either upgrade them to at least the bundled version with the tool managing them, "+
				"or hand them over to the Cilium Operator by labeling them with "+crdManagedByLabel+"="+crdManagedByValue+" and restarting the operator. "+
				"Please refer to the Gateway API installation docs.",
			logfields.Error, conflicts,
			logfields.Version, targets[0].Annotations[crds.BundleVersionAnnotation],
		)
		health.Degraded("Gateway API CRDs conflict", conflicts)
		return nil
	}

	health.OK(fmt.Sprintf("Gateway API CRDs %s (%s channel) installed", targets[0].Annotations[crds.BundleVersionAnnotation], targets[0].Annotations[crds.ChannelAnnotation]))
	return nil
}

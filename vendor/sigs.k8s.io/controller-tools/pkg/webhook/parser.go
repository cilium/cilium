/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package webhook contains libraries for generating webhookconfig manifests
// from markers in Go source files.
//
// The markers take the form:
//
//  +kubebuilder:webhook:webhookVersions=<[]string>,failurePolicy=<string>,matchPolicy=<string>,groups=<[]string>,resources=<[]string>,verbs=<[]string>,versions=<[]string>,name=<string>,path=<string>,mutating=<bool>,sideEffects=<string>,admissionReviewVersions=<[]string>
package webhook

import (
	"fmt"
	"strings"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"

	"sigs.k8s.io/controller-tools/pkg/genall"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// The default {Mutating,Validating}WebhookConfiguration version to generate.
const (
	defaultWebhookVersion = "v1"
)

var (
	// ConfigDefinition s a marker for defining Webhook manifests.
	// Call ToWebhook on the value to get a Kubernetes Webhook.
	ConfigDefinition = markers.Must(markers.MakeDefinition("kubebuilder:webhook", markers.DescribesPackage, Config{}))
)

// supportedWebhookVersions returns currently supported API version of {Mutating,Validating}WebhookConfiguration.
func supportedWebhookVersions() []string {
	return []string{defaultWebhookVersion, "v1beta1"}
}

// +controllertools:marker:generateHelp:category=Webhook

// Config specifies how a webhook should be served.
//
// It specifies only the details that are intrinsic to the application serving
// it (e.g. the resources it can handle, or the path it serves on).
type Config struct {
	// Mutating marks this as a mutating webhook (it's validating only if false)
	//
	// Mutating webhooks are allowed to change the object in their response,
	// and are called *before* all validating webhooks.  Mutating webhooks may
	// choose to reject an object, similarly to a validating webhook.
	Mutating bool
	// FailurePolicy specifies what should happen if the API server cannot reach the webhook.
	//
	// It may be either "ignore" (to skip the webhook and continue on) or "fail" (to reject
	// the object in question).
	FailurePolicy string
	// MatchPolicy defines how the "rules" list is used to match incoming requests.
	// Allowed values are "Exact" (match only if it exactly matches the specified rule)
	// or "Equivalent" (match a request if it modifies a resource listed in rules, even via another API group or version).
	MatchPolicy string `marker:",optional"`
	// SideEffects specify whether calling the webhook will have side effects.
	// This has an impact on dry runs and `kubectl diff`: if the sideEffect is "Unknown" (the default) or "Some", then
	// the API server will not call the webhook on a dry-run request and fails instead.
	// If the value is "None", then the webhook has no side effects and the API server will call it on dry-run.
	// If the value is "NoneOnDryRun", then the webhook is responsible for inspecting the "dryRun" property of the
	// AdmissionReview sent in the request, and avoiding side effects if that value is "true."
	SideEffects string `marker:",optional"`

	// Groups specifies the API groups that this webhook receives requests for.
	Groups []string
	// Resources specifies the API resources that this webhook receives requests for.
	Resources []string
	// Verbs specifies the Kubernetes API verbs that this webhook receives requests for.
	//
	// Only modification-like verbs may be specified.
	// May be "create", "update", "delete", "connect", or "*" (for all).
	Verbs []string
	// Versions specifies the API versions that this webhook receives requests for.
	Versions []string

	// Name indicates the name of this webhook configuration. Should be a domain with at least three segments separated by dots
	Name string

	// Path specifies that path that the API server should connect to this webhook on. Must be
	// prefixed with a '/validate-' or '/mutate-' depending on the type, and followed by
	// $GROUP-$VERSION-$KIND where all values are lower-cased and the periods in the group
	// are substituted for hyphens. For example, a validating webhook path for type
	// batch.tutorial.kubebuilder.io/v1,Kind=CronJob would be
	// /validate-batch-tutorial-kubebuilder-io-v1-cronjob
	Path string

	// WebhookVersions specifies the target API versions of the {Mutating,Validating}WebhookConfiguration objects
	// itself to generate.  Defaults to v1.
	WebhookVersions []string `marker:"webhookVersions,optional"`

	// AdmissionReviewVersions is an ordered list of preferred `AdmissionReview`
	// versions the Webhook expects.
	// For generating v1 {Mutating,Validating}WebhookConfiguration, this is mandatory.
	// For generating v1beta1 {Mutating,Validating}WebhookConfiguration, this is optional, and default to v1beta1.
	AdmissionReviewVersions []string `marker:"admissionReviewVersions,optional"`
}

// verbToAPIVariant converts a marker's verb to the proper value for the API.
// Unrecognized verbs are passed through.
func verbToAPIVariant(verbRaw string) admissionregv1.OperationType {
	switch strings.ToLower(verbRaw) {
	case strings.ToLower(string(admissionregv1.Create)):
		return admissionregv1.Create
	case strings.ToLower(string(admissionregv1.Update)):
		return admissionregv1.Update
	case strings.ToLower(string(admissionregv1.Delete)):
		return admissionregv1.Delete
	case strings.ToLower(string(admissionregv1.Connect)):
		return admissionregv1.Connect
	case strings.ToLower(string(admissionregv1.OperationAll)):
		return admissionregv1.OperationAll
	default:
		return admissionregv1.OperationType(verbRaw)
	}
}

// ToMutatingWebhook converts this rule to its Kubernetes API form.
func (c Config) ToMutatingWebhook() (admissionregv1.MutatingWebhook, error) {
	if !c.Mutating {
		return admissionregv1.MutatingWebhook{}, fmt.Errorf("%s is a validating webhook", c.Name)
	}

	matchPolicy, err := c.matchPolicy()
	if err != nil {
		return admissionregv1.MutatingWebhook{}, err
	}

	return admissionregv1.MutatingWebhook{
		Name:                    c.Name,
		Rules:                   c.rules(),
		FailurePolicy:           c.failurePolicy(),
		MatchPolicy:             matchPolicy,
		ClientConfig:            c.clientConfig(),
		SideEffects:             c.sideEffects(),
		AdmissionReviewVersions: c.AdmissionReviewVersions,
	}, nil
}

// ToValidatingWebhook converts this rule to its Kubernetes API form.
func (c Config) ToValidatingWebhook() (admissionregv1.ValidatingWebhook, error) {
	if c.Mutating {
		return admissionregv1.ValidatingWebhook{}, fmt.Errorf("%s is a mutating webhook", c.Name)
	}

	matchPolicy, err := c.matchPolicy()
	if err != nil {
		return admissionregv1.ValidatingWebhook{}, err
	}

	return admissionregv1.ValidatingWebhook{
		Name:                    c.Name,
		Rules:                   c.rules(),
		FailurePolicy:           c.failurePolicy(),
		MatchPolicy:             matchPolicy,
		ClientConfig:            c.clientConfig(),
		SideEffects:             c.sideEffects(),
		AdmissionReviewVersions: c.AdmissionReviewVersions,
	}, nil
}

// rules returns the configuration of what operations on what
// resources/subresources a webhook should care about.
func (c Config) rules() []admissionregv1.RuleWithOperations {
	whConfig := admissionregv1.RuleWithOperations{
		Rule: admissionregv1.Rule{
			APIGroups:   c.Groups,
			APIVersions: c.Versions,
			Resources:   c.Resources,
		},
		Operations: make([]admissionregv1.OperationType, len(c.Verbs)),
	}

	for i, verbRaw := range c.Verbs {
		whConfig.Operations[i] = verbToAPIVariant(verbRaw)
	}

	// fix the group names, since letting people type "core" is nice
	for i, group := range whConfig.APIGroups {
		if group == "core" {
			whConfig.APIGroups[i] = ""
		}
	}

	return []admissionregv1.RuleWithOperations{whConfig}
}

// failurePolicy converts the string value to the proper value for the API.
// Unrecognized values are passed through.
func (c Config) failurePolicy() *admissionregv1.FailurePolicyType {
	var failurePolicy admissionregv1.FailurePolicyType
	switch strings.ToLower(c.FailurePolicy) {
	case strings.ToLower(string(admissionregv1.Ignore)):
		failurePolicy = admissionregv1.Ignore
	case strings.ToLower(string(admissionregv1.Fail)):
		failurePolicy = admissionregv1.Fail
	default:
		failurePolicy = admissionregv1.FailurePolicyType(c.FailurePolicy)
	}
	return &failurePolicy
}

// matchPolicy converts the string value to the proper value for the API.
func (c Config) matchPolicy() (*admissionregv1.MatchPolicyType, error) {
	var matchPolicy admissionregv1.MatchPolicyType
	switch strings.ToLower(c.MatchPolicy) {
	case strings.ToLower(string(admissionregv1.Exact)):
		matchPolicy = admissionregv1.Exact
	case strings.ToLower(string(admissionregv1.Equivalent)):
		matchPolicy = admissionregv1.Equivalent
	case "":
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown value %q for matchPolicy", c.MatchPolicy)
	}
	return &matchPolicy, nil
}

// clientConfig returns the client config for a webhook.
func (c Config) clientConfig() admissionregv1.WebhookClientConfig {
	path := c.Path
	return admissionregv1.WebhookClientConfig{
		Service: &admissionregv1.ServiceReference{
			Name:      "webhook-service",
			Namespace: "system",
			Path:      &path,
		},
	}
}

// sideEffects returns the sideEffects config for a webhook.
func (c Config) sideEffects() *admissionregv1.SideEffectClass {
	var sideEffects admissionregv1.SideEffectClass
	switch strings.ToLower(c.SideEffects) {
	case strings.ToLower(string(admissionregv1.SideEffectClassNone)):
		sideEffects = admissionregv1.SideEffectClassNone
	case strings.ToLower(string(admissionregv1.SideEffectClassNoneOnDryRun)):
		sideEffects = admissionregv1.SideEffectClassNoneOnDryRun
	case strings.ToLower(string(admissionregv1.SideEffectClassSome)):
		sideEffects = admissionregv1.SideEffectClassSome
	case "":
		return nil
	default:
		return nil
	}
	return &sideEffects
}

// webhookVersions returns the target API versions of the {Mutating,Validating}WebhookConfiguration objects for a webhook.
func (c Config) webhookVersions() ([]string, error) {
	// If WebhookVersions is not specified, we default it to `v1`.
	if len(c.WebhookVersions) == 0 {
		return []string{defaultWebhookVersion}, nil
	}
	supportedWebhookVersions := sets.NewString(supportedWebhookVersions()...)
	for _, version := range c.WebhookVersions {
		if !supportedWebhookVersions.Has(version) {
			return nil, fmt.Errorf("unsupported webhook version: %s", version)
		}
	}
	return sets.NewString(c.WebhookVersions...).UnsortedList(), nil
}

// +controllertools:marker:generateHelp

// Generator generates (partial) {Mutating,Validating}WebhookConfiguration objects.
type Generator struct{}

func (Generator) RegisterMarkers(into *markers.Registry) error {
	if err := into.Register(ConfigDefinition); err != nil {
		return err
	}
	into.AddHelp(ConfigDefinition, Config{}.Help())
	return nil
}

func (Generator) Generate(ctx *genall.GenerationContext) error {
	supportedWebhookVersions := supportedWebhookVersions()
	mutatingCfgs := make(map[string][]admissionregv1.MutatingWebhook, len(supportedWebhookVersions))
	validatingCfgs := make(map[string][]admissionregv1.ValidatingWebhook, len(supportedWebhookVersions))
	for _, root := range ctx.Roots {
		markerSet, err := markers.PackageMarkers(ctx.Collector, root)
		if err != nil {
			root.AddError(err)
		}

		for _, cfg := range markerSet[ConfigDefinition.Name] {
			cfg := cfg.(Config)
			webhookVersions, err := cfg.webhookVersions()
			if err != nil {
				return err
			}
			if cfg.Mutating {
				w, err := cfg.ToMutatingWebhook()
				if err != nil {
					return err
				}
				for _, webhookVersion := range webhookVersions {
					mutatingCfgs[webhookVersion] = append(mutatingCfgs[webhookVersion], w)
				}
			} else {
				w, err := cfg.ToValidatingWebhook()
				if err != nil {
					return err
				}
				for _, webhookVersion := range webhookVersions {
					validatingCfgs[webhookVersion] = append(validatingCfgs[webhookVersion], w)
				}
			}
		}
	}

	versionedWebhooks := make(map[string][]interface{}, len(supportedWebhookVersions))
	for _, version := range supportedWebhookVersions {
		if cfgs, ok := mutatingCfgs[version]; ok {
			// All webhook config versions in supportedWebhookVersions have the same general form, with a few
			// stricter requirements for v1. Since no conversion scheme exists for webhook configs, the v1
			// type can be used for all versioned types in this context.
			objRaw := &admissionregv1.MutatingWebhookConfiguration{}
			objRaw.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   admissionregv1.SchemeGroupVersion.Group,
				Version: version,
				Kind:    "MutatingWebhookConfiguration",
			})
			objRaw.SetName("mutating-webhook-configuration")
			objRaw.Webhooks = cfgs
			switch version {
			case admissionregv1.SchemeGroupVersion.Version:
				for i := range objRaw.Webhooks {
					// SideEffects is required in admissionregistration/v1, if this is not set or set to `Some` or `Known`,
					// return an error
					if err := checkSideEffectsForV1(objRaw.Webhooks[i].SideEffects); err != nil {
						return err
					}
					// AdmissionReviewVersions is required in admissionregistration/v1, if this is not set,
					// return an error
					if len(objRaw.Webhooks[i].AdmissionReviewVersions) == 0 {
						return fmt.Errorf("AdmissionReviewVersions is mandatory for v1 {Mutating,Validating}WebhookConfiguration")
					}
				}
			}
			versionedWebhooks[version] = append(versionedWebhooks[version], objRaw)
		}

		if cfgs, ok := validatingCfgs[version]; ok {
			// All webhook config versions in supportedWebhookVersions have the same general form, with a few
			// stricter requirements for v1. Since no conversion scheme exists for webhook configs, the v1
			// type can be used for all versioned types in this context.
			objRaw := &admissionregv1.ValidatingWebhookConfiguration{}
			objRaw.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   admissionregv1.SchemeGroupVersion.Group,
				Version: version,
				Kind:    "ValidatingWebhookConfiguration",
			})
			objRaw.SetName("validating-webhook-configuration")
			objRaw.Webhooks = cfgs
			switch version {
			case admissionregv1.SchemeGroupVersion.Version:
				for i := range objRaw.Webhooks {
					// SideEffects is required in admissionregistration/v1, if this is not set or set to `Some` or `Known`,
					// return an error
					if err := checkSideEffectsForV1(objRaw.Webhooks[i].SideEffects); err != nil {
						return err
					}
					// AdmissionReviewVersions is required in admissionregistration/v1, if this is not set,
					// return an error
					if len(objRaw.Webhooks[i].AdmissionReviewVersions) == 0 {
						return fmt.Errorf("AdmissionReviewVersions is mandatory for v1 {Mutating,Validating}WebhookConfiguration")
					}
				}
			}
			versionedWebhooks[version] = append(versionedWebhooks[version], objRaw)
		}
	}

	for k, v := range versionedWebhooks {
		var fileName string
		if k == defaultWebhookVersion {
			fileName = fmt.Sprintf("manifests.yaml")
		} else {
			fileName = fmt.Sprintf("manifests.%s.yaml", k)
		}
		if err := ctx.WriteYAML(fileName, v...); err != nil {
			return err
		}
	}
	return nil
}

func checkSideEffectsForV1(sideEffects *admissionregv1.SideEffectClass) error {
	if sideEffects == nil {
		return fmt.Errorf("SideEffects is required for creating v1 {Mutating,Validating}WebhookConfiguration")
	}
	if *sideEffects == admissionregv1.SideEffectClassUnknown ||
		*sideEffects == admissionregv1.SideEffectClassSome {
		return fmt.Errorf("SideEffects should not be set to `Some` or `Unknown` for v1 {Mutating,Validating}WebhookConfiguration")
	}
	return nil
}

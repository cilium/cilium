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
//	+kubebuilder:webhook:webhookVersions=<[]string>,failurePolicy=<string>,matchPolicy=<string>,groups=<[]string>,resources=<[]string>,verbs=<[]string>,versions=<[]string>,name=<string>,path=<string>,mutating=<bool>,sideEffects=<string>,timeoutSeconds=<int>,admissionReviewVersions=<[]string>,reinvocationPolicy=<string>
package webhook

import (
	"fmt"
	"sort"
	"strings"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-tools/pkg/genall"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// The default {Mutating,Validating}WebhookConfiguration version to generate.
const (
	v1                    = "v1"
	defaultWebhookVersion = v1
)

var (
	// ConfigDefinition is a marker for defining Webhook manifests.
	// Call ToWebhook on the value to get a Kubernetes Webhook.
	ConfigDefinition = markers.Must(markers.MakeDefinition("kubebuilder:webhook", markers.DescribesPackage, Config{}))
	// WebhookConfigDefinition is a marker for defining MutatingWebhookConfiguration or ValidatingWebhookConfiguration manifests.
	WebhookConfigDefinition = markers.Must(markers.MakeDefinition("kubebuilder:webhookconfiguration", markers.DescribesPackage, WebhookConfig{}))
)

// supportedWebhookVersions returns currently supported API version of {Mutating,Validating}WebhookConfiguration.
func supportedWebhookVersions() []string {
	return []string{defaultWebhookVersion}
}

// +controllertools:marker:generateHelp

type WebhookConfig struct {
	// Mutating marks this as a mutating webhook (it's validating only if false)
	//
	// Mutating webhooks are allowed to change the object in their response,
	// and are called *before* all validating webhooks.  Mutating webhooks may
	// choose to reject an object, similarly to a validating webhook.
	Mutating bool
	// Name indicates the name of the K8s MutatingWebhookConfiguration or ValidatingWebhookConfiguration object.
	Name string `marker:"name,optional"`
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
	// TimeoutSeconds allows configuring how long the API server should wait for a webhook to respond before treating the call as a failure.
	// If the timeout expires before the webhook responds, the webhook call will be ignored or the API call will be rejected based on the failure policy.
	// The timeout value must be between 1 and 30 seconds.
	// The timeout for an admission webhook defaults to 10 seconds.
	TimeoutSeconds int `marker:",optional"`

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
	Path string `marker:"path,optional"`

	// WebhookVersions specifies the target API versions of the {Mutating,Validating}WebhookConfiguration objects
	// itself to generate. The only supported value is v1. Defaults to v1.
	WebhookVersions []string `marker:"webhookVersions,optional"`

	// AdmissionReviewVersions is an ordered list of preferred `AdmissionReview`
	// versions the Webhook expects.
	AdmissionReviewVersions []string `marker:"admissionReviewVersions"`

	// ReinvocationPolicy allows mutating webhooks to request reinvocation after other mutations
	//
	// To allow mutating admission plugins to observe changes made by other plugins,
	// built-in mutating admission plugins are re-run if a mutating webhook modifies
	// an object, and mutating webhooks can specify a reinvocationPolicy to control
	// whether they are reinvoked as well.
	ReinvocationPolicy string `marker:"reinvocationPolicy,optional"`

	// URL allows mutating webhooks configuration to specify an external URL when generating
	// the manifests, instead of using the internal service communication. Should be in format of
	// https://address:port/path
	// When this option is specified, the serviceConfig.Service is removed from webhook the manifest.
	// The URL configuration should be between quotes.
	// `url` cannot be specified when `path` is specified.
	URL string `marker:"url,optional"`
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

// ToMutatingWebhookConfiguration converts this WebhookConfig to its Kubernetes API form.
func (c WebhookConfig) ToMutatingWebhookConfiguration() (admissionregv1.MutatingWebhookConfiguration, error) {
	if !c.Mutating {
		return admissionregv1.MutatingWebhookConfiguration{}, fmt.Errorf("%s is a validating webhook", c.Name)
	}

	return admissionregv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: c.Name,
		},
	}, nil
}

// ToValidatingWebhookConfiguration converts this WebhookConfig to its Kubernetes API form.
func (c WebhookConfig) ToValidatingWebhookConfiguration() (admissionregv1.ValidatingWebhookConfiguration, error) {
	if c.Mutating {
		return admissionregv1.ValidatingWebhookConfiguration{}, fmt.Errorf("%s is a mutating webhook", c.Name)
	}

	return admissionregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: c.Name,
		},
	}, nil
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

	clientConfig, err := c.clientConfig()
	if err != nil {
		return admissionregv1.MutatingWebhook{}, err
	}

	return admissionregv1.MutatingWebhook{
		Name:                    c.Name,
		Rules:                   c.rules(),
		FailurePolicy:           c.failurePolicy(),
		MatchPolicy:             matchPolicy,
		ClientConfig:            clientConfig,
		SideEffects:             c.sideEffects(),
		TimeoutSeconds:          c.timeoutSeconds(),
		AdmissionReviewVersions: c.AdmissionReviewVersions,
		ReinvocationPolicy:      c.reinvocationPolicy(),
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

	clientConfig, err := c.clientConfig()
	if err != nil {
		return admissionregv1.ValidatingWebhook{}, err
	}

	return admissionregv1.ValidatingWebhook{
		Name:                    c.Name,
		Rules:                   c.rules(),
		FailurePolicy:           c.failurePolicy(),
		MatchPolicy:             matchPolicy,
		ClientConfig:            clientConfig,
		SideEffects:             c.sideEffects(),
		TimeoutSeconds:          c.timeoutSeconds(),
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
func (c Config) clientConfig() (admissionregv1.WebhookClientConfig, error) {
	if (c.Path != "" && c.URL != "") || (c.Path == "" && c.URL == "") {
		return admissionregv1.WebhookClientConfig{}, fmt.Errorf("`url` or `path` markers are required and mutually exclusive")
	}

	path := c.Path
	if path != "" {
		return admissionregv1.WebhookClientConfig{
			Service: &admissionregv1.ServiceReference{
				Name:      "webhook-service",
				Namespace: "system",
				Path:      &path,
			},
		}, nil
	}

	url := c.URL
	return admissionregv1.WebhookClientConfig{
		URL: &url,
	}, nil
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

// timeoutSeconds returns the timeoutSeconds config for a webhook.
func (c Config) timeoutSeconds() *int32 {
	if c.TimeoutSeconds != 0 {
		timeoutSeconds := int32(c.TimeoutSeconds)
		return &timeoutSeconds
	}
	return nil
}

// reinvocationPolicy returns the reinvocationPolicy config for a mutating webhook.
func (c Config) reinvocationPolicy() *admissionregv1.ReinvocationPolicyType {
	var reinvocationPolicy admissionregv1.ReinvocationPolicyType
	switch strings.ToLower(c.ReinvocationPolicy) {
	case strings.ToLower(string(admissionregv1.NeverReinvocationPolicy)):
		reinvocationPolicy = admissionregv1.NeverReinvocationPolicy
	case strings.ToLower(string(admissionregv1.IfNeededReinvocationPolicy)):
		reinvocationPolicy = admissionregv1.IfNeededReinvocationPolicy
	default:
		return nil
	}
	return &reinvocationPolicy
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
type Generator struct {
	// HeaderFile specifies the header text (e.g. license) to prepend to generated files.
	HeaderFile string `marker:",optional"`

	// Year specifies the year to substitute for " YEAR" in the header file.
	Year string `marker:",optional"`
}

func (Generator) RegisterMarkers(into *markers.Registry) error {
	if err := into.Register(ConfigDefinition); err != nil {
		return err
	}
	if err := into.Register(WebhookConfigDefinition); err != nil {
		return err
	}
	into.AddHelp(ConfigDefinition, Config{}.Help())
	into.AddHelp(WebhookConfigDefinition, Config{}.Help())
	return nil
}

func (g Generator) Generate(ctx *genall.GenerationContext) error {
	supportedWebhookVersions := supportedWebhookVersions()
	mutatingCfgs := make(map[string][]admissionregv1.MutatingWebhook, len(supportedWebhookVersions))
	validatingCfgs := make(map[string][]admissionregv1.ValidatingWebhook, len(supportedWebhookVersions))
	var mutatingWebhookCfgs admissionregv1.MutatingWebhookConfiguration
	var validatingWebhookCfgs admissionregv1.ValidatingWebhookConfiguration

	for _, root := range ctx.Roots {
		markerSet, err := markers.PackageMarkers(ctx.Collector, root)
		if err != nil {
			root.AddError(err)
		}

		webhookCfgs := markerSet[WebhookConfigDefinition.Name]
		var hasValidatingWebhookConfig, hasMutatingWebhookConfig bool = false, false
		for _, webhookCfg := range webhookCfgs {
			webhookCfg := webhookCfg.(WebhookConfig)

			if webhookCfg.Mutating {
				if hasMutatingWebhookConfig {
					return fmt.Errorf("duplicate mutating %s with name %s", WebhookConfigDefinition.Name, webhookCfg.Name)
				}

				if mutatingWebhookCfgs, err = webhookCfg.ToMutatingWebhookConfiguration(); err != nil {
					return err
				}

				hasMutatingWebhookConfig = true
			} else {
				if hasValidatingWebhookConfig {
					return fmt.Errorf("duplicate validating %s with name %s", WebhookConfigDefinition.Name, webhookCfg.Name)
				}

				if validatingWebhookCfgs, err = webhookCfg.ToValidatingWebhookConfiguration(); err != nil {
					return err
				}

				hasValidatingWebhookConfig = true
			}
		}

		cfgs := markerSet[ConfigDefinition.Name]
		sort.SliceStable(cfgs, func(i, j int) bool {
			return cfgs[i].(Config).Name < cfgs[j].(Config).Name
		})

		for _, cfg := range cfgs {
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
			var objRaw *admissionregv1.MutatingWebhookConfiguration
			if mutatingWebhookCfgs.Name != "" {
				objRaw = &mutatingWebhookCfgs
			} else {
				// The only possible version in supportedWebhookVersions is v1,
				// so use it for all versioned types in this context.
				objRaw = &admissionregv1.MutatingWebhookConfiguration{}
				objRaw.SetName("mutating-webhook-configuration")
			}
			objRaw.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   admissionregv1.SchemeGroupVersion.Group,
				Version: version,
				Kind:    "MutatingWebhookConfiguration",
			})
			objRaw.Webhooks = cfgs

			for i := range objRaw.Webhooks {
				// SideEffects is required in admissionregistration/v1, if this is not set or set to `Some` or `Known`,
				// return an error
				if err := checkSideEffectsForV1(objRaw.Webhooks[i].SideEffects); err != nil {
					return err
				}
				// TimeoutSeconds must be nil or between 1 and 30 seconds, otherwise,
				// return an error
				if err := checkTimeoutSeconds(objRaw.Webhooks[i].TimeoutSeconds); err != nil {
					return err
				}
				// AdmissionReviewVersions is required in admissionregistration/v1, if this is not set,
				// return an error
				if len(objRaw.Webhooks[i].AdmissionReviewVersions) == 0 {
					return fmt.Errorf("AdmissionReviewVersions is mandatory for v1 {Mutating,Validating}WebhookConfiguration")
				}
			}
			versionedWebhooks[version] = append(versionedWebhooks[version], objRaw)
		}

		if cfgs, ok := validatingCfgs[version]; ok {
			var objRaw *admissionregv1.ValidatingWebhookConfiguration
			if validatingWebhookCfgs.Name != "" {
				objRaw = &validatingWebhookCfgs
			} else {
				// The only possible version in supportedWebhookVersions is v1,
				// so use it for all versioned types in this context.
				objRaw = &admissionregv1.ValidatingWebhookConfiguration{}
				objRaw.SetName("validating-webhook-configuration")
			}
			objRaw.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   admissionregv1.SchemeGroupVersion.Group,
				Version: version,
				Kind:    "ValidatingWebhookConfiguration",
			})
			objRaw.Webhooks = cfgs

			for i := range objRaw.Webhooks {
				// SideEffects is required in admissionregistration/v1, if this is not set or set to `Some` or `Known`,
				// return an error
				if err := checkSideEffectsForV1(objRaw.Webhooks[i].SideEffects); err != nil {
					return err
				}
				// TimeoutSeconds must be nil or between 1 and 30 seconds, otherwise,
				// return an error
				if err := checkTimeoutSeconds(objRaw.Webhooks[i].TimeoutSeconds); err != nil {
					return err
				}
				// AdmissionReviewVersions is required in admissionregistration/v1, if this is not set,
				// return an error
				if len(objRaw.Webhooks[i].AdmissionReviewVersions) == 0 {
					return fmt.Errorf("AdmissionReviewVersions is mandatory for v1 {Mutating,Validating}WebhookConfiguration")
				}
			}
			versionedWebhooks[version] = append(versionedWebhooks[version], objRaw)
		}
	}

	var headerText string
	if g.HeaderFile != "" {
		headerBytes, err := ctx.ReadFile(g.HeaderFile)
		if err != nil {
			return err
		}
		headerText = string(headerBytes)
	}
	headerText = strings.ReplaceAll(headerText, " YEAR", " "+g.Year)

	for k, v := range versionedWebhooks {
		var fileName string
		if k == defaultWebhookVersion {
			fileName = "manifests.yaml"
		} else {
			fileName = fmt.Sprintf("manifests.%s.yaml", k)
		}
		if err := ctx.WriteYAML(fileName, headerText, v, genall.WithTransform(genall.TransformRemoveCreationTimestamp)); err != nil {
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

func checkTimeoutSeconds(timeoutSeconds *int32) error {
	if timeoutSeconds != nil && (*timeoutSeconds < 1 || *timeoutSeconds > 30) {
		return fmt.Errorf("TimeoutSeconds must be between 1 and 30 seconds")
	}
	return nil
}

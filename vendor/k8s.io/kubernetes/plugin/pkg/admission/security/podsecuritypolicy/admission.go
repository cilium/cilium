/*
Copyright 2016 The Kubernetes Authors.

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

package podsecuritypolicy

import (
	"fmt"
	"io"
	"strings"

	"github.com/golang/glog"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	informers "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion"
	extensionslisters "k8s.io/kubernetes/pkg/client/listers/extensions/internalversion"
	kubeapiserveradmission "k8s.io/kubernetes/pkg/kubeapiserver/admission"
	psp "k8s.io/kubernetes/pkg/security/podsecuritypolicy"
	psputil "k8s.io/kubernetes/pkg/security/podsecuritypolicy/util"
	sc "k8s.io/kubernetes/pkg/securitycontext"
	"k8s.io/kubernetes/pkg/serviceaccount"
	"k8s.io/kubernetes/pkg/util/maps"
)

const (
	PluginName = "PodSecurityPolicy"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		plugin := NewPlugin(psp.NewSimpleStrategyFactory(), getMatchingPolicies, true)
		return plugin, nil
	})
}

// PSPMatchFn allows plugging in how PSPs are matched against user information.
type PSPMatchFn func(lister extensionslisters.PodSecurityPolicyLister, user user.Info, sa user.Info, authz authorizer.Authorizer, namespace string) ([]*extensions.PodSecurityPolicy, error)

// podSecurityPolicyPlugin holds state for and implements the admission plugin.
type podSecurityPolicyPlugin struct {
	*admission.Handler
	strategyFactory  psp.StrategyFactory
	pspMatcher       PSPMatchFn
	failOnNoPolicies bool
	authz            authorizer.Authorizer
	lister           extensionslisters.PodSecurityPolicyLister
}

// SetAuthorizer sets the authorizer.
func (plugin *podSecurityPolicyPlugin) SetAuthorizer(authz authorizer.Authorizer) {
	plugin.authz = authz
}

// Validate ensures an authorizer is set.
func (plugin *podSecurityPolicyPlugin) Validate() error {
	if plugin.authz == nil {
		return fmt.Errorf("%s requires an authorizer", PluginName)
	}
	if plugin.lister == nil {
		return fmt.Errorf("%s requires a lister", PluginName)
	}
	return nil
}

var _ admission.Interface = &podSecurityPolicyPlugin{}
var _ kubeapiserveradmission.WantsAuthorizer = &podSecurityPolicyPlugin{}
var _ kubeapiserveradmission.WantsInternalKubeInformerFactory = &podSecurityPolicyPlugin{}

// NewPlugin creates a new PSP admission plugin.
func NewPlugin(strategyFactory psp.StrategyFactory, pspMatcher PSPMatchFn, failOnNoPolicies bool) *podSecurityPolicyPlugin {
	return &podSecurityPolicyPlugin{
		Handler:          admission.NewHandler(admission.Create, admission.Update),
		strategyFactory:  strategyFactory,
		pspMatcher:       pspMatcher,
		failOnNoPolicies: failOnNoPolicies,
	}
}

func (a *podSecurityPolicyPlugin) SetInternalKubeInformerFactory(f informers.SharedInformerFactory) {
	podSecurityPolicyInformer := f.Extensions().InternalVersion().PodSecurityPolicies()
	a.lister = podSecurityPolicyInformer.Lister()
	a.SetReadyFunc(podSecurityPolicyInformer.Informer().HasSynced)
}

// Admit determines if the pod should be admitted based on the requested security context
// and the available PSPs.
//
// 1.  Find available PSPs.
// 2.  Create the providers, includes setting pre-allocated values if necessary.
// 3.  Try to generate and validate a PSP with providers.  If we find one then admit the pod
//     with the validated PSP.  If we don't find any reject the pod and give all errors from the
//     failed attempts.
func (c *podSecurityPolicyPlugin) Admit(a admission.Attributes) error {
	if a.GetResource().GroupResource() != api.Resource("pods") {
		return nil
	}

	if len(a.GetSubresource()) != 0 {
		return nil
	}

	pod, ok := a.GetObject().(*api.Pod)
	// if we can't convert then we don't handle this object so just return
	if !ok {
		return nil
	}

	// get all constraints that are usable by the user
	glog.V(4).Infof("getting pod security policies for pod %s (generate: %s)", pod.Name, pod.GenerateName)
	var saInfo user.Info
	if len(pod.Spec.ServiceAccountName) > 0 {
		saInfo = serviceaccount.UserInfo(a.GetNamespace(), pod.Spec.ServiceAccountName, "")
	}

	matchedPolicies, err := c.pspMatcher(c.lister, a.GetUserInfo(), saInfo, c.authz, a.GetNamespace())
	if err != nil {
		return admission.NewForbidden(a, err)
	}

	// if we have no policies and want to succeed then return.  Otherwise we'll end up with no
	// providers and fail with "unable to validate against any pod security policy" below.
	if len(matchedPolicies) == 0 && !c.failOnNoPolicies {
		return nil
	}

	providers, errs := c.createProvidersFromPolicies(matchedPolicies, pod.Namespace)
	logProviders(pod, providers, errs)

	if len(providers) == 0 {
		return admission.NewForbidden(a, fmt.Errorf("no providers available to validate pod request"))
	}

	// all containers in a single pod must validate under a single provider or we will reject the request
	validationErrs := field.ErrorList{}
	for _, provider := range providers {
		if errs := assignSecurityContext(provider, pod, field.NewPath(fmt.Sprintf("provider %s: ", provider.GetPSPName()))); len(errs) > 0 {
			validationErrs = append(validationErrs, errs...)
			continue
		}

		// the entire pod validated, annotate and accept the pod
		glog.V(4).Infof("pod %s (generate: %s) validated against provider %s", pod.Name, pod.GenerateName, provider.GetPSPName())
		if pod.ObjectMeta.Annotations == nil {
			pod.ObjectMeta.Annotations = map[string]string{}
		}
		pod.ObjectMeta.Annotations[psputil.ValidatedPSPAnnotation] = provider.GetPSPName()
		return nil
	}

	// we didn't validate against any provider, reject the pod and give the errors for each attempt
	glog.V(4).Infof("unable to validate pod %s (generate: %s) against any pod security policy: %v", pod.Name, pod.GenerateName, validationErrs)
	return admission.NewForbidden(a, fmt.Errorf("unable to validate against any pod security policy: %v", validationErrs))
}

// assignSecurityContext creates a security context for each container in the pod
// and validates that the sc falls within the psp constraints.  All containers must validate against
// the same psp or is not considered valid.
func assignSecurityContext(provider psp.Provider, pod *api.Pod, fldPath *field.Path) field.ErrorList {
	generatedSCs := make([]*api.SecurityContext, len(pod.Spec.Containers))
	var generatedInitSCs []*api.SecurityContext

	errs := field.ErrorList{}

	psc, pscAnnotations, err := provider.CreatePodSecurityContext(pod)
	if err != nil {
		errs = append(errs, field.Invalid(field.NewPath("spec", "securityContext"), pod.Spec.SecurityContext, err.Error()))
	}

	// save the original PSC and validate the generated PSC.  Leave the generated PSC
	// set for container generation/validation.  We will reset to original post container
	// validation.
	originalPSC := pod.Spec.SecurityContext
	pod.Spec.SecurityContext = psc
	originalAnnotations := maps.CopySS(pod.Annotations)
	pod.Annotations = pscAnnotations
	errs = append(errs, provider.ValidatePodSecurityContext(pod, field.NewPath("spec", "securityContext"))...)

	// Note: this is not changing the original container, we will set container SCs later so long
	// as all containers validated under the same PSP.
	for i, containerCopy := range pod.Spec.InitContainers {
		// We will determine the effective security context for the container and validate against that
		// since that is how the sc provider will eventually apply settings in the runtime.
		// This results in an SC that is based on the Pod's PSC with the set fields from the container
		// overriding pod level settings.
		containerCopy.SecurityContext = sc.InternalDetermineEffectiveSecurityContext(pod, &containerCopy)

		sc, scAnnotations, err := provider.CreateContainerSecurityContext(pod, &containerCopy)
		if err != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec", "initContainers").Index(i).Child("securityContext"), "", err.Error()))
			continue
		}
		generatedInitSCs = append(generatedInitSCs, sc)

		containerCopy.SecurityContext = sc
		pod.Annotations = scAnnotations
		errs = append(errs, provider.ValidateContainerSecurityContext(pod, &containerCopy, field.NewPath("spec", "initContainers").Index(i).Child("securityContext"))...)
	}

	// Note: this is not changing the original container, we will set container SCs later so long
	// as all containers validated under the same PSP.
	for i, containerCopy := range pod.Spec.Containers {
		// We will determine the effective security context for the container and validate against that
		// since that is how the sc provider will eventually apply settings in the runtime.
		// This results in an SC that is based on the Pod's PSC with the set fields from the container
		// overriding pod level settings.
		containerCopy.SecurityContext = sc.InternalDetermineEffectiveSecurityContext(pod, &containerCopy)

		sc, scAnnotations, err := provider.CreateContainerSecurityContext(pod, &containerCopy)
		if err != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec", "containers").Index(i).Child("securityContext"), "", err.Error()))
			continue
		}
		generatedSCs[i] = sc

		containerCopy.SecurityContext = sc
		pod.Annotations = scAnnotations
		errs = append(errs, provider.ValidateContainerSecurityContext(pod, &containerCopy, field.NewPath("spec", "containers").Index(i).Child("securityContext"))...)
	}

	if len(errs) > 0 {
		// ensure psc is not mutated if there are errors
		pod.Spec.SecurityContext = originalPSC
		pod.Annotations = originalAnnotations
		return errs
	}

	// if we've reached this code then we've generated and validated an SC for every container in the
	// pod so let's apply what we generated.  Note: the psc is already applied.
	for i, sc := range generatedInitSCs {
		pod.Spec.InitContainers[i].SecurityContext = sc
	}
	for i, sc := range generatedSCs {
		pod.Spec.Containers[i].SecurityContext = sc
	}
	return nil
}

// createProvidersFromPolicies creates providers from the constraints supplied.
func (c *podSecurityPolicyPlugin) createProvidersFromPolicies(psps []*extensions.PodSecurityPolicy, namespace string) ([]psp.Provider, []error) {
	var (
		// collected providers
		providers []psp.Provider
		// collected errors to return
		errs []error
	)

	for _, constraint := range psps {
		provider, err := psp.NewSimpleProvider(constraint, namespace, c.strategyFactory)
		if err != nil {
			errs = append(errs, fmt.Errorf("error creating provider for PSP %s: %v", constraint.Name, err))
			continue
		}
		providers = append(providers, provider)
	}
	return providers, errs
}

// getMatchingPolicies returns policies from the lister.  For now this returns everything
// in the future it can filter based on UserInfo and permissions.
//
// TODO: this will likely need optimization since the initial implementation will
// always query for authorization.  Needs scale testing and possibly checking against
// a cache.
func getMatchingPolicies(lister extensionslisters.PodSecurityPolicyLister, user user.Info, sa user.Info, authz authorizer.Authorizer, namespace string) ([]*extensions.PodSecurityPolicy, error) {
	matchedPolicies := make([]*extensions.PodSecurityPolicy, 0)

	list, err := lister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	for _, constraint := range list {
		if authorizedForPolicy(user, namespace, constraint, authz) || authorizedForPolicy(sa, namespace, constraint, authz) {
			matchedPolicies = append(matchedPolicies, constraint)
		}
	}

	return matchedPolicies, nil
}

// authorizedForPolicy returns true if info is authorized to perform the "use" verb on the policy resource.
func authorizedForPolicy(info user.Info, namespace string, policy *extensions.PodSecurityPolicy, authz authorizer.Authorizer) bool {
	if info == nil {
		return false
	}
	attr := buildAttributes(info, namespace, policy)
	allowed, reason, err := authz.Authorize(attr)
	if err != nil {
		glog.V(5).Infof("cannot authorize for policy: %v,%v", reason, err)
	}
	return allowed
}

// buildAttributes builds an attributes record for a SAR based on the user info and policy.
func buildAttributes(info user.Info, namespace string, policy *extensions.PodSecurityPolicy) authorizer.Attributes {
	// check against the namespace that the pod is being created in to allow per-namespace PSP grants.
	attr := authorizer.AttributesRecord{
		User:            info,
		Verb:            "use",
		Namespace:       namespace,
		Name:            policy.Name,
		APIGroup:        extensions.GroupName,
		Resource:        "podsecuritypolicies",
		ResourceRequest: true,
	}
	return attr
}

// logProviders logs what providers were found for the pod as well as any errors that were encountered
// while creating providers.
func logProviders(pod *api.Pod, providers []psp.Provider, providerCreationErrs []error) {
	for _, err := range providerCreationErrs {
		glog.V(4).Infof("provider creation error: %v", err)
	}

	if len(providers) == 0 {
		glog.V(4).Infof("unable to validate pod %s (generate: %s) against any provider.", pod.Name, pod.GenerateName)
		return
	}

	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.GetPSPName()
	}
	glog.V(4).Infof("validating pod %s (generate: %s) against providers: %s", pod.Name, pod.GenerateName, strings.Join(names, ","))
}

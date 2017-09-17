/*
Copyright 2017 The Kubernetes Authors.

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

package internalclientset

import (
	glog "github.com/golang/glog"
	discovery "k8s.io/client-go/discovery"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"
	admissionregistrationinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/admissionregistration/internalversion"
	appsinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/apps/internalversion"
	authenticationinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/authentication/internalversion"
	authorizationinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/authorization/internalversion"
	autoscalinginternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/autoscaling/internalversion"
	batchinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/batch/internalversion"
	certificatesinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/certificates/internalversion"
	coreinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/core/internalversion"
	extensionsinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/extensions/internalversion"
	networkinginternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/networking/internalversion"
	policyinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/policy/internalversion"
	rbacinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/internalversion"
	schedulinginternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/scheduling/internalversion"
	settingsinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/settings/internalversion"
	storageinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/storage/internalversion"
)

type Interface interface {
	Discovery() discovery.DiscoveryInterface
	Admissionregistration() admissionregistrationinternalversion.AdmissionregistrationInterface
	Core() coreinternalversion.CoreInterface
	Apps() appsinternalversion.AppsInterface
	Authentication() authenticationinternalversion.AuthenticationInterface
	Authorization() authorizationinternalversion.AuthorizationInterface
	Autoscaling() autoscalinginternalversion.AutoscalingInterface
	Batch() batchinternalversion.BatchInterface
	Certificates() certificatesinternalversion.CertificatesInterface
	Extensions() extensionsinternalversion.ExtensionsInterface
	Networking() networkinginternalversion.NetworkingInterface
	Policy() policyinternalversion.PolicyInterface
	Rbac() rbacinternalversion.RbacInterface
	Scheduling() schedulinginternalversion.SchedulingInterface
	Settings() settingsinternalversion.SettingsInterface
	Storage() storageinternalversion.StorageInterface
}

// Clientset contains the clients for groups. Each group has exactly one
// version included in a Clientset.
type Clientset struct {
	*discovery.DiscoveryClient
	admissionregistration *admissionregistrationinternalversion.AdmissionregistrationClient
	core                  *coreinternalversion.CoreClient
	apps                  *appsinternalversion.AppsClient
	authentication        *authenticationinternalversion.AuthenticationClient
	authorization         *authorizationinternalversion.AuthorizationClient
	autoscaling           *autoscalinginternalversion.AutoscalingClient
	batch                 *batchinternalversion.BatchClient
	certificates          *certificatesinternalversion.CertificatesClient
	extensions            *extensionsinternalversion.ExtensionsClient
	networking            *networkinginternalversion.NetworkingClient
	policy                *policyinternalversion.PolicyClient
	rbac                  *rbacinternalversion.RbacClient
	scheduling            *schedulinginternalversion.SchedulingClient
	settings              *settingsinternalversion.SettingsClient
	storage               *storageinternalversion.StorageClient
}

// Admissionregistration retrieves the AdmissionregistrationClient
func (c *Clientset) Admissionregistration() admissionregistrationinternalversion.AdmissionregistrationInterface {
	return c.admissionregistration
}

// Core retrieves the CoreClient
func (c *Clientset) Core() coreinternalversion.CoreInterface {
	return c.core
}

// Apps retrieves the AppsClient
func (c *Clientset) Apps() appsinternalversion.AppsInterface {
	return c.apps
}

// Authentication retrieves the AuthenticationClient
func (c *Clientset) Authentication() authenticationinternalversion.AuthenticationInterface {
	return c.authentication
}

// Authorization retrieves the AuthorizationClient
func (c *Clientset) Authorization() authorizationinternalversion.AuthorizationInterface {
	return c.authorization
}

// Autoscaling retrieves the AutoscalingClient
func (c *Clientset) Autoscaling() autoscalinginternalversion.AutoscalingInterface {
	return c.autoscaling
}

// Batch retrieves the BatchClient
func (c *Clientset) Batch() batchinternalversion.BatchInterface {
	return c.batch
}

// Certificates retrieves the CertificatesClient
func (c *Clientset) Certificates() certificatesinternalversion.CertificatesInterface {
	return c.certificates
}

// Extensions retrieves the ExtensionsClient
func (c *Clientset) Extensions() extensionsinternalversion.ExtensionsInterface {
	return c.extensions
}

// Networking retrieves the NetworkingClient
func (c *Clientset) Networking() networkinginternalversion.NetworkingInterface {
	return c.networking
}

// Policy retrieves the PolicyClient
func (c *Clientset) Policy() policyinternalversion.PolicyInterface {
	return c.policy
}

// Rbac retrieves the RbacClient
func (c *Clientset) Rbac() rbacinternalversion.RbacInterface {
	return c.rbac
}

// Scheduling retrieves the SchedulingClient
func (c *Clientset) Scheduling() schedulinginternalversion.SchedulingInterface {
	return c.scheduling
}

// Settings retrieves the SettingsClient
func (c *Clientset) Settings() settingsinternalversion.SettingsInterface {
	return c.settings
}

// Storage retrieves the StorageClient
func (c *Clientset) Storage() storageinternalversion.StorageInterface {
	return c.storage
}

// Discovery retrieves the DiscoveryClient
func (c *Clientset) Discovery() discovery.DiscoveryInterface {
	if c == nil {
		return nil
	}
	return c.DiscoveryClient
}

// NewForConfig creates a new Clientset for the given config.
func NewForConfig(c *rest.Config) (*Clientset, error) {
	configShallowCopy := *c
	if configShallowCopy.RateLimiter == nil && configShallowCopy.QPS > 0 {
		configShallowCopy.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(configShallowCopy.QPS, configShallowCopy.Burst)
	}
	var cs Clientset
	var err error
	cs.admissionregistration, err = admissionregistrationinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.core, err = coreinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.apps, err = appsinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.authentication, err = authenticationinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.authorization, err = authorizationinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.autoscaling, err = autoscalinginternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.batch, err = batchinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.certificates, err = certificatesinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.extensions, err = extensionsinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.networking, err = networkinginternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.policy, err = policyinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.rbac, err = rbacinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.scheduling, err = schedulinginternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.settings, err = settingsinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.storage, err = storageinternalversion.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}

	cs.DiscoveryClient, err = discovery.NewDiscoveryClientForConfig(&configShallowCopy)
	if err != nil {
		glog.Errorf("failed to create the DiscoveryClient: %v", err)
		return nil, err
	}
	return &cs, nil
}

// NewForConfigOrDie creates a new Clientset for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *Clientset {
	var cs Clientset
	cs.admissionregistration = admissionregistrationinternalversion.NewForConfigOrDie(c)
	cs.core = coreinternalversion.NewForConfigOrDie(c)
	cs.apps = appsinternalversion.NewForConfigOrDie(c)
	cs.authentication = authenticationinternalversion.NewForConfigOrDie(c)
	cs.authorization = authorizationinternalversion.NewForConfigOrDie(c)
	cs.autoscaling = autoscalinginternalversion.NewForConfigOrDie(c)
	cs.batch = batchinternalversion.NewForConfigOrDie(c)
	cs.certificates = certificatesinternalversion.NewForConfigOrDie(c)
	cs.extensions = extensionsinternalversion.NewForConfigOrDie(c)
	cs.networking = networkinginternalversion.NewForConfigOrDie(c)
	cs.policy = policyinternalversion.NewForConfigOrDie(c)
	cs.rbac = rbacinternalversion.NewForConfigOrDie(c)
	cs.scheduling = schedulinginternalversion.NewForConfigOrDie(c)
	cs.settings = settingsinternalversion.NewForConfigOrDie(c)
	cs.storage = storageinternalversion.NewForConfigOrDie(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClientForConfigOrDie(c)
	return &cs
}

// New creates a new Clientset for the given RESTClient.
func New(c rest.Interface) *Clientset {
	var cs Clientset
	cs.admissionregistration = admissionregistrationinternalversion.New(c)
	cs.core = coreinternalversion.New(c)
	cs.apps = appsinternalversion.New(c)
	cs.authentication = authenticationinternalversion.New(c)
	cs.authorization = authorizationinternalversion.New(c)
	cs.autoscaling = autoscalinginternalversion.New(c)
	cs.batch = batchinternalversion.New(c)
	cs.certificates = certificatesinternalversion.New(c)
	cs.extensions = extensionsinternalversion.New(c)
	cs.networking = networkinginternalversion.New(c)
	cs.policy = policyinternalversion.New(c)
	cs.rbac = rbacinternalversion.New(c)
	cs.scheduling = schedulinginternalversion.New(c)
	cs.settings = settingsinternalversion.New(c)
	cs.storage = storageinternalversion.New(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClient(c)
	return &cs
}

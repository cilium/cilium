/*
Copyright 2020 The Kubernetes Authors.

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

package webhook

import (
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	admissionregv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var (
	conversionScheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(admissionregv1.AddToScheme(conversionScheme))
	utilruntime.Must(admissionregv1beta1.AddToScheme(conversionScheme))
}

// MutatingWebhookConfigurationAsVersion converts a MutatingWebhookConfiguration from the canonical internal form (currently v1) to some external form.
func MutatingWebhookConfigurationAsVersion(original *admissionregv1.MutatingWebhookConfiguration, gv schema.GroupVersion) (runtime.Object, error) {
	return conversionScheme.ConvertToVersion(original, gv)
}

// ValidatingWebhookConfigurationAsVersion converts a ValidatingWebhookConfiguration from the canonical internal form (currently v1) to some external form.
func ValidatingWebhookConfigurationAsVersion(original *admissionregv1.ValidatingWebhookConfiguration, gv schema.GroupVersion) (runtime.Object, error) {
	return conversionScheme.ConvertToVersion(original, gv)
}

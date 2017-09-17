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

package user

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

type nonRoot struct{}

var _ RunAsUserStrategy = &nonRoot{}

func NewRunAsNonRoot(options *extensions.RunAsUserStrategyOptions) (RunAsUserStrategy, error) {
	return &nonRoot{}, nil
}

// Generate creates the uid based on policy rules.  This strategy does return a UID.  It assumes
// that the user will specify a UID or the container image specifies a UID.
func (s *nonRoot) Generate(pod *api.Pod, container *api.Container) (*int64, error) {
	return nil, nil
}

// Validate ensures that the specified values fall within the range of the strategy.  Validation
// of this will pass if either the UID is not set, assuming that the image will provided the UID
// or if the UID is set it is not root.  Validation will fail if RunAsNonRoot is set to false.
// In order to work properly this assumes that the kubelet performs a final check on runAsUser
// or the image UID when runAsUser is nil.
func (s *nonRoot) Validate(pod *api.Pod, container *api.Container) field.ErrorList {
	allErrs := field.ErrorList{}
	securityContextPath := field.NewPath("securityContext")
	if container.SecurityContext == nil {
		detail := fmt.Sprintf("unable to validate nil security context for container %s", container.Name)
		allErrs = append(allErrs, field.Invalid(securityContextPath, container.SecurityContext, detail))
		return allErrs
	}
	if container.SecurityContext.RunAsNonRoot != nil && *container.SecurityContext.RunAsNonRoot == false {
		detail := fmt.Sprintf("RunAsNonRoot must be true for container %s", container.Name)
		allErrs = append(allErrs, field.Invalid(securityContextPath.Child("runAsNonRoot"), *container.SecurityContext.RunAsNonRoot, detail))
		return allErrs
	}
	if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
		detail := fmt.Sprintf("running with the root UID is forbidden by the pod security policy for container %s", container.Name)
		allErrs = append(allErrs, field.Invalid(securityContextPath.Child("runAsUser"), *container.SecurityContext.RunAsUser, detail))
		return allErrs
	}
	return allErrs
}

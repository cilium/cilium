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

package util

import (
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
)

// ResourceAttributesFrom combines the API object information and the user.Info from the context to build a full authorizer.AttributesRecord for resource access
func ResourceAttributesFrom(user user.Info, in authorizationapi.ResourceAttributes) authorizer.AttributesRecord {
	return authorizer.AttributesRecord{
		User:            user,
		Verb:            in.Verb,
		Namespace:       in.Namespace,
		APIGroup:        in.Group,
		APIVersion:      in.Version,
		Resource:        in.Resource,
		Subresource:     in.Subresource,
		Name:            in.Name,
		ResourceRequest: true,
	}
}

// NonResourceAttributesFrom combines the API object information and the user.Info from the context to build a full authorizer.AttributesRecord for non resource access
func NonResourceAttributesFrom(user user.Info, in authorizationapi.NonResourceAttributes) authorizer.AttributesRecord {
	return authorizer.AttributesRecord{
		User:            user,
		ResourceRequest: false,
		Path:            in.Path,
		Verb:            in.Verb,
	}
}

func convertToUserInfoExtra(extra map[string]authorizationapi.ExtraValue) map[string][]string {
	if extra == nil {
		return nil
	}
	ret := map[string][]string{}
	for k, v := range extra {
		ret[k] = []string(v)
	}

	return ret
}

// AuthorizationAttributesFrom takes a spec and returns the proper authz attributes to check it.
func AuthorizationAttributesFrom(spec authorizationapi.SubjectAccessReviewSpec) authorizer.AttributesRecord {
	userToCheck := &user.DefaultInfo{
		Name:   spec.User,
		Groups: spec.Groups,
		UID:    spec.UID,
		Extra:  convertToUserInfoExtra(spec.Extra),
	}

	var authorizationAttributes authorizer.AttributesRecord
	if spec.ResourceAttributes != nil {
		authorizationAttributes = ResourceAttributesFrom(userToCheck, *spec.ResourceAttributes)
	} else {
		authorizationAttributes = NonResourceAttributesFrom(userToCheck, *spec.NonResourceAttributes)
	}

	return authorizationAttributes
}

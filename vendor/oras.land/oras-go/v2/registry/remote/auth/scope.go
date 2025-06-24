/*
Copyright The ORAS Authors.
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

package auth

import (
	"context"
	"slices"
	"strings"

	"oras.land/oras-go/v2/registry"
)

// Actions used in scopes.
// Reference: https://distribution.github.io/distribution/spec/auth/scope/
const (
	// ActionPull represents generic read access for resources of the repository
	// type.
	ActionPull = "pull"

	// ActionPush represents generic write access for resources of the
	// repository type.
	ActionPush = "push"

	// ActionDelete represents the delete permission for resources of the
	// repository type.
	ActionDelete = "delete"
)

// ScopeRegistryCatalog is the scope for registry catalog access.
const ScopeRegistryCatalog = "registry:catalog:*"

// ScopeRepository returns a repository scope with given actions.
// Reference: https://distribution.github.io/distribution/spec/auth/scope/
func ScopeRepository(repository string, actions ...string) string {
	actions = cleanActions(actions)
	if repository == "" || len(actions) == 0 {
		return ""
	}
	return strings.Join([]string{
		"repository",
		repository,
		strings.Join(actions, ","),
	}, ":")
}

// AppendRepositoryScope returns a new context containing scope hints for the
// auth client to fetch bearer tokens with the given actions on the repository.
// If called multiple times, the new scopes will be appended to the existing
// scopes. The resulted scopes are de-duplicated.
//
// For example, uploading blob to the repository "hello-world" does HEAD request
// first then POST and PUT. The HEAD request will return a challenge for scope
// `repository:hello-world:pull`, and the auth client will fetch a token for
// that challenge. Later, the POST request will return a challenge for scope
// `repository:hello-world:push`, and the auth client will fetch a token for
// that challenge again. By invoking AppendRepositoryScope with the actions
// [ActionPull] and [ActionPush] for the repository `hello-world`,
// the auth client with cache is hinted to fetch a token via a single token
// fetch request for all the HEAD, POST, PUT requests.
func AppendRepositoryScope(ctx context.Context, ref registry.Reference, actions ...string) context.Context {
	if len(actions) == 0 {
		return ctx
	}
	scope := ScopeRepository(ref.Repository, actions...)
	return AppendScopesForHost(ctx, ref.Host(), scope)
}

// scopesContextKey is the context key for scopes.
type scopesContextKey struct{}

// WithScopes returns a context with scopes added. Scopes are de-duplicated.
// Scopes are used as hints for the auth client to fetch bearer tokens with
// larger scopes.
//
// For example, uploading blob to the repository "hello-world" does HEAD request
// first then POST and PUT. The HEAD request will return a challenge for scope
// `repository:hello-world:pull`, and the auth client will fetch a token for
// that challenge. Later, the POST request will return a challenge for scope
// `repository:hello-world:push`, and the auth client will fetch a token for
// that challenge again. By invoking WithScopes with the scope
// `repository:hello-world:pull,push`, the auth client with cache is hinted to
// fetch a token via a single token fetch request for all the HEAD, POST, PUT
// requests.
//
// Passing an empty list of scopes will virtually remove the scope hints in the
// context.
//
// Reference: https://distribution.github.io/distribution/spec/auth/scope/
func WithScopes(ctx context.Context, scopes ...string) context.Context {
	scopes = CleanScopes(scopes)
	return context.WithValue(ctx, scopesContextKey{}, scopes)
}

// AppendScopes appends additional scopes to the existing scopes in the context
// and returns a new context. The resulted scopes are de-duplicated.
// The append operation does modify the existing scope in the context passed in.
func AppendScopes(ctx context.Context, scopes ...string) context.Context {
	if len(scopes) == 0 {
		return ctx
	}
	return WithScopes(ctx, append(GetScopes(ctx), scopes...)...)
}

// GetScopes returns the scopes in the context.
func GetScopes(ctx context.Context) []string {
	if scopes, ok := ctx.Value(scopesContextKey{}).([]string); ok {
		return slices.Clone(scopes)
	}
	return nil
}

// scopesForHostContextKey is the context key for per-host scopes.
type scopesForHostContextKey string

// WithScopesForHost returns a context with per-host scopes added.
// Scopes are de-duplicated.
// Scopes are used as hints for the auth client to fetch bearer tokens with
// larger scopes.
//
// For example, uploading blob to the repository "hello-world" does HEAD request
// first then POST and PUT. The HEAD request will return a challenge for scope
// `repository:hello-world:pull`, and the auth client will fetch a token for
// that challenge. Later, the POST request will return a challenge for scope
// `repository:hello-world:push`, and the auth client will fetch a token for
// that challenge again. By invoking WithScopesForHost with the scope
// `repository:hello-world:pull,push`, the auth client with cache is hinted to
// fetch a token via a single token fetch request for all the HEAD, POST, PUT
// requests.
//
// Passing an empty list of scopes will virtually remove the scope hints in the
// context for the given host.
//
// Reference: https://distribution.github.io/distribution/spec/auth/scope/
func WithScopesForHost(ctx context.Context, host string, scopes ...string) context.Context {
	scopes = CleanScopes(scopes)
	return context.WithValue(ctx, scopesForHostContextKey(host), scopes)
}

// AppendScopesForHost appends additional scopes to the existing scopes
// in the context for the given host and returns a new context.
// The resulted scopes are de-duplicated.
// The append operation does modify the existing scope in the context passed in.
func AppendScopesForHost(ctx context.Context, host string, scopes ...string) context.Context {
	if len(scopes) == 0 {
		return ctx
	}
	oldScopes := GetScopesForHost(ctx, host)
	return WithScopesForHost(ctx, host, append(oldScopes, scopes...)...)
}

// GetScopesForHost returns the scopes in the context for the given host,
// excluding global scopes added by [WithScopes] and [AppendScopes].
func GetScopesForHost(ctx context.Context, host string) []string {
	if scopes, ok := ctx.Value(scopesForHostContextKey(host)).([]string); ok {
		return slices.Clone(scopes)
	}
	return nil
}

// GetAllScopesForHost returns the scopes in the context for the given host,
// including global scopes added by [WithScopes] and [AppendScopes].
func GetAllScopesForHost(ctx context.Context, host string) []string {
	scopes := GetScopesForHost(ctx, host)
	globalScopes := GetScopes(ctx)

	if len(scopes) == 0 {
		return globalScopes
	}
	if len(globalScopes) == 0 {
		return scopes
	}
	// re-clean the scopes
	allScopes := append(scopes, globalScopes...)
	return CleanScopes(allScopes)
}

// CleanScopes merges and sort the actions in ascending order if the scopes have
// the same resource type and name. The final scopes are sorted in ascending
// order. In other words, the scopes passed in are de-duplicated and sorted.
// Therefore, the output of this function is deterministic.
//
// If there is a wildcard `*` in the action, other actions in the same resource
// type and name are ignored.
func CleanScopes(scopes []string) []string {
	// fast paths
	switch len(scopes) {
	case 0:
		return nil
	case 1:
		scope := scopes[0]
		i := strings.LastIndex(scope, ":")
		if i == -1 {
			return []string{scope}
		}
		actionList := strings.Split(scope[i+1:], ",")
		actionList = cleanActions(actionList)
		if len(actionList) == 0 {
			return nil
		}
		actions := strings.Join(actionList, ",")
		scope = scope[:i+1] + actions
		return []string{scope}
	}

	// slow path
	var result []string

	// merge recognizable scopes
	resourceTypes := make(map[string]map[string]map[string]struct{})
	for _, scope := range scopes {
		// extract resource type
		i := strings.Index(scope, ":")
		if i == -1 {
			result = append(result, scope)
			continue
		}
		resourceType := scope[:i]

		// extract resource name and actions
		rest := scope[i+1:]
		i = strings.LastIndex(rest, ":")
		if i == -1 {
			result = append(result, scope)
			continue
		}
		resourceName := rest[:i]
		actions := rest[i+1:]
		if actions == "" {
			// drop scope since no action found
			continue
		}

		// add to the intermediate map for de-duplication
		namedActions := resourceTypes[resourceType]
		if namedActions == nil {
			namedActions = make(map[string]map[string]struct{})
			resourceTypes[resourceType] = namedActions
		}
		actionSet := namedActions[resourceName]
		if actionSet == nil {
			actionSet = make(map[string]struct{})
			namedActions[resourceName] = actionSet
		}
		for _, action := range strings.Split(actions, ",") {
			if action != "" {
				actionSet[action] = struct{}{}
			}
		}
	}

	// reconstruct scopes
	for resourceType, namedActions := range resourceTypes {
		for resourceName, actionSet := range namedActions {
			if len(actionSet) == 0 {
				continue
			}
			var actions []string
			for action := range actionSet {
				if action == "*" {
					actions = []string{"*"}
					break
				}
				actions = append(actions, action)
			}
			slices.Sort(actions)
			scope := resourceType + ":" + resourceName + ":" + strings.Join(actions, ",")
			result = append(result, scope)
		}
	}

	// sort and return
	slices.Sort(result)
	return result
}

// cleanActions removes the duplicated actions and sort in ascending order.
// If there is a wildcard `*` in the action, other actions are ignored.
func cleanActions(actions []string) []string {
	// fast paths
	switch len(actions) {
	case 0:
		return nil
	case 1:
		if actions[0] == "" {
			return nil
		}
		return actions
	}

	// slow path
	slices.Sort(actions)
	n := 0
	for i := range len(actions) {
		if actions[i] == "*" {
			return []string{"*"}
		}
		if actions[i] != actions[n] {
			n++
			if n != i {
				actions[n] = actions[i]
			}
		}
	}
	n++
	if actions[0] == "" {
		if n == 1 {
			return nil
		}
		return actions[1:n]
	}
	return actions[:n]
}

/*
Copyright 2019 The Kubernetes Authors.

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

// Package rbac contain libraries for generating RBAC manifests from RBAC
// markers in Go source files.
//
// The markers take the form:
//
//	+kubebuilder:rbac:groups=<groups>,resources=<resources>,resourceNames=<resource names>,verbs=<verbs>,urls=<non resource urls>
package rbac

import (
	"fmt"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-tools/pkg/genall"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

var (
	// RuleDefinition is a marker for defining RBAC rules.
	// Call ToRule on the value to get a Kubernetes RBAC policy rule.
	RuleDefinition = markers.Must(markers.MakeDefinition("kubebuilder:rbac", markers.DescribesPackage, Rule{}))
)

// +controllertools:marker:generateHelp:category=RBAC

// Rule specifies an RBAC rule to all access to some resources or non-resource URLs.
//
// RBAC markers are used to generate ClusterRole or Role manifests.
// Multiple markers can be combined to build comprehensive RBAC policies.
//
// Examples:
//
//	// Basic resource access
//	// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch
//
//	// Core API group (use empty string)
//	// +kubebuilder:rbac:groups="",resources=pods;services,verbs=get;list;watch
//
//	// Multiple API groups and resources
//	// +kubebuilder:rbac:groups=apps;batch,resources=deployments;jobs,verbs=get;list;watch;create;update;patch;delete
//
//	// Access to resource status or scale subresources
//	// +kubebuilder:rbac:groups=apps,resources=deployments/status,verbs=get;update;patch
//	// +kubebuilder:rbac:groups=apps,resources=deployments/scale,verbs=get;update
//
//	// Access to specific resource instances by name
//	// +kubebuilder:rbac:groups="",resources=configmaps,resourceNames=my-config,verbs=get
//
//	// Non-resource URLs (for metrics, healthz, etc.)
//	// +kubebuilder:rbac:urls=/metrics;/healthz,verbs=get
//
//	// Namespace-scoped Role instead of ClusterRole
//	// +kubebuilder:rbac:groups="",namespace=my-namespace,resources=secrets,verbs=get;list;watch
//
//	// Custom role name
//	// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list,roleName=deployment-reader
type Rule struct {
	// Groups specifies the API groups that this rule encompasses.
	// Use empty string ("") for the core API group.
	// Multiple groups can be specified separated by semicolons.
	// Example: "apps;batch" or "" (for core group).
	Groups []string `marker:",optional"`

	// Resources specifies the API resources that this rule encompasses.
	// Multiple resources can be specified separated by semicolons.
	// Subresources can be specified with a slash (e.g., "deployments/status").
	// Example: "deployments;pods" or "deployments/status".
	Resources []string `marker:",optional"`

	// ResourceNames specifies the names of the API resources that this rule encompasses.
	//
	// Create requests cannot be restricted by resourcename, as the object's name
	// is not known at authorization time.
	// Multiple names can be specified separated by semicolons.
	// Example: "my-config;my-secret".
	ResourceNames []string `marker:",optional"`

	// Verbs specifies the (lowercase) kubernetes API verbs that this rule encompasses.
	// Common verbs: "get", "list", "watch", "create", "update", "patch", "delete".
	// Use "*" for all verbs.
	// Multiple verbs must be specified separated by semicolons.
	// Example: "get;list;watch".
	Verbs []string

	// URL specifies the non-resource URLs that this rule encompasses.
	// Non-resource URLs are paths that don't represent resources, like "/metrics" or "/healthz".
	// Multiple URLs can be specified separated by semicolons.
	// Example: "/metrics;/healthz".
	URLs []string `marker:"urls,optional"`

	// Namespace specifies the scope of the Rule.
	// If not set, the Rule belongs to the generated ClusterRole.
	// If set, the Rule belongs to a Role, whose namespace is specified by this field.
	// Example: "my-namespace".
	Namespace string `marker:",optional"`

	// RoleName specifies a custom name for the Role or ClusterRole.
	// If not set, uses the default roleName from the generator.
	// Useful for avoiding name conflicts when the same roleName is used across multiple namespaces.
	//
	// Example: When using namespace-scoped RBAC markers with kustomize's global namespace transformation,
	// multiple Roles might end up in the same namespace with identical names, causing an "ID conflict" error.
	// Use roleName to ensure each Role has a unique name:
	//
	//   // +kubebuilder:rbac:groups=apps,namespace=infrastructure,roleName=infra-manager,resources=deployments,verbs=get;list
	//   // +kubebuilder:rbac:groups="",namespace=users,roleName=user-secrets,resources=secrets,verbs=get
	//
	// This generates Roles named "infra-manager" and "user-secrets" instead of both being "manager-role".
	RoleName string `marker:"roleName,optional"`
}

// ruleKey represents the resources and non-resources a Rule applies.
type ruleKey struct {
	Groups        string
	Resources     string
	ResourceNames string
	URLs          string
}

func (key ruleKey) String() string {
	return fmt.Sprintf("%s + %s + %s + %s", key.Groups, key.Resources, key.ResourceNames, key.URLs)
}

// key normalizes the Rule and returns a ruleKey object.
func (r *Rule) key() ruleKey {
	r.normalize()
	return ruleKey{
		Groups:        strings.Join(r.Groups, "&"),
		Resources:     strings.Join(r.Resources, "&"),
		ResourceNames: strings.Join(r.ResourceNames, "&"),
		URLs:          strings.Join(r.URLs, "&"),
	}
}

func (r *Rule) keyWithGroupResourceNamesURLsVerbs() string {
	key := r.key()
	verbs := strings.Join(r.Verbs, "&")
	return fmt.Sprintf("%s + %s + %s + %s", key.Groups, key.ResourceNames, key.URLs, verbs)
}

func (r *Rule) keyWithResourcesResourceNamesURLsVerbs() string {
	key := r.key()
	verbs := strings.Join(r.Verbs, "&")
	return fmt.Sprintf("%s + %s + %s + %s", key.Resources, key.ResourceNames, key.URLs, verbs)
}

func (r *Rule) keyWitGroupResourcesResourceNamesVerbs() string {
	key := r.key()
	verbs := strings.Join(r.Verbs, "&")
	return fmt.Sprintf("%s + %s + %s + %s", key.Groups, key.Resources, key.ResourceNames, verbs)
}

// addVerbs adds new verbs into a Rule.
// The duplicates in `r.Verbs` will be removed, and then `r.Verbs` will be sorted.
func (r *Rule) addVerbs(verbs []string) {
	r.Verbs = removeDupAndSort(append(r.Verbs, verbs...))
}

// normalize removes duplicates from each field of a Rule, and sorts each field.
func (r *Rule) normalize() {
	r.Groups = removeDupAndSort(r.Groups)
	r.Resources = removeDupAndSort(r.Resources)
	r.ResourceNames = removeDupAndSort(r.ResourceNames)
	r.Verbs = removeDupAndSort(r.Verbs)
	r.URLs = removeDupAndSort(r.URLs)
}

// removeDupAndSort removes duplicates in strs, sorts the items, and returns a
// new slice of strings.
func removeDupAndSort(strs []string) []string {
	if len(strs) == 0 {
		return nil
	}

	set := make(map[string]bool)
	for _, str := range strs {
		if _, ok := set[str]; !ok {
			set[str] = true
		}
	}

	result := make([]string, 0, len(set))
	for str := range set {
		result = append(result, str)
	}
	slices.Sort(result)
	return result
}

// ToRule converts this rule to its Kubernetes API form.
func (r *Rule) ToRule() rbacv1.PolicyRule {
	return rbacv1.PolicyRule{
		APIGroups:       r.Groups,
		Verbs:           r.Verbs,
		Resources:       r.Resources,
		ResourceNames:   r.ResourceNames,
		NonResourceURLs: r.URLs,
	}
}

// +controllertools:marker:generateHelp

// Generator generates ClusterRole objects.
type Generator struct {
	// RoleName sets the name of the generated ClusterRole.
	RoleName string

	// FileName sets the file name for the generated manifest(s). If not set, defaults to "role.yaml".
	FileName string `marker:",optional"`

	// HeaderFile specifies the header text (e.g. license) to prepend to generated files.
	HeaderFile string `marker:",optional"`

	// Year specifies the year to substitute for " YEAR" in the header file.
	Year string `marker:",optional"`
}

func (Generator) RegisterMarkers(into *markers.Registry) error {
	if err := into.Register(RuleDefinition); err != nil {
		return err
	}
	into.AddHelp(RuleDefinition, Rule{}.Help())
	return nil
}

// GenerateRoles generate a slice of objs representing either a ClusterRole or a Role object
// The order of the objs in the returned slice is stable and determined by their namespaces.
func GenerateRoles(ctx *genall.GenerationContext, roleName string) ([]any, error) {
	// Group rules by namespace:roleName combination
	// Key format: "namespace:roleName" or ":roleName" for ClusterRole
	type nsRoleKey struct {
		namespace string
		roleName  string
	}
	rulesByNSRole := make(map[nsRoleKey][]*Rule)

	for _, root := range ctx.Roots {
		markerSet, err := markers.PackageMarkers(ctx.Collector, root)
		if err != nil {
			root.AddError(err)
		}

		// group RBAC markers by namespace and roleName, separate by resource
		for _, markerValue := range markerSet[RuleDefinition.Name] {
			rule := markerValue.(Rule)
			// Use custom roleName if specified, otherwise use default
			effectiveRoleName := rule.RoleName
			if effectiveRoleName == "" {
				effectiveRoleName = roleName
			}
			key := nsRoleKey{namespace: rule.Namespace, roleName: effectiveRoleName}

			if len(rule.Resources) == 0 {
				// Add a rule without any resource if Resources is empty.
				r := Rule{
					Groups:        rule.Groups,
					Resources:     []string{},
					ResourceNames: rule.ResourceNames,
					URLs:          rule.URLs,
					Namespace:     rule.Namespace,
					RoleName:      effectiveRoleName,
					Verbs:         rule.Verbs,
				}
				rulesByNSRole[key] = append(rulesByNSRole[key], &r)
				continue
			}
			for _, resource := range rule.Resources {
				r := Rule{
					Groups:        rule.Groups,
					Resources:     []string{resource},
					ResourceNames: rule.ResourceNames,
					URLs:          rule.URLs,
					Namespace:     rule.Namespace,
					RoleName:      effectiveRoleName,
					Verbs:         rule.Verbs,
				}
				rulesByNSRole[key] = append(rulesByNSRole[key], &r)
			}
		}
	}

	// NormalizeRules merge Rule with the same ruleKey and sort the Rules
	NormalizeRules := func(rules []*Rule) []rbacv1.PolicyRule {
		ruleMap := make(map[ruleKey]*Rule)
		// all the Rules having the same ruleKey will be merged into the first Rule
		for _, rule := range rules {
			// fix the group name first, since letting people type "core" is nice
			for i, name := range rule.Groups {
				if name == "core" {
					rule.Groups[i] = ""
				}
			}

			key := rule.key()
			if _, ok := ruleMap[key]; !ok {
				ruleMap[key] = rule
				continue
			}
			ruleMap[key].addVerbs(rule.Verbs)
		}

		// deduplicate resources
		// 1. create map based on key without resources
		ruleMapWithoutResources := make(map[string][]*Rule)
		for _, rule := range ruleMap {
			// get key without Resources
			key := rule.keyWithGroupResourceNamesURLsVerbs()
			ruleMapWithoutResources[key] = append(ruleMapWithoutResources[key], rule)
		}
		// 2. merge to ruleMap
		ruleMap = make(map[ruleKey]*Rule)
		for _, rules := range ruleMapWithoutResources {
			rule := rules[0]
			for _, mergeRule := range rules[1:] {
				rule.Resources = append(rule.Resources, mergeRule.Resources...)
			}

			key := rule.key()
			ruleMap[key] = rule
		}

		// deduplicate groups
		// 1. create map based on key without group
		ruleMapWithoutGroup := make(map[string][]*Rule)
		for _, rule := range ruleMap {
			// get key without Group
			key := rule.keyWithResourcesResourceNamesURLsVerbs()
			ruleMapWithoutGroup[key] = append(ruleMapWithoutGroup[key], rule)
		}
		// 2. merge to ruleMap
		ruleMap = make(map[ruleKey]*Rule)
		for _, rules := range ruleMapWithoutGroup {
			rule := rules[0]
			for _, mergeRule := range rules[1:] {
				rule.Groups = append(rule.Groups, mergeRule.Groups...)
			}
			key := rule.key()
			ruleMap[key] = rule
		}

		// deduplicate URLs
		// 1. create map based on key without URLs
		ruleMapWithoutURLs := make(map[string][]*Rule)
		for _, rule := range ruleMap {
			// get key without Group
			key := rule.keyWitGroupResourcesResourceNamesVerbs()
			ruleMapWithoutURLs[key] = append(ruleMapWithoutURLs[key], rule)
		}
		// 2. merge to ruleMap
		ruleMap = make(map[ruleKey]*Rule)
		for _, rules := range ruleMapWithoutURLs {
			rule := rules[0]
			for _, mergeRule := range rules[1:] {
				rule.URLs = append(rule.URLs, mergeRule.URLs...)
			}
			key := rule.key()
			ruleMap[key] = rule
		}

		// sort the Rules in rules according to their ruleKeys
		keys := make([]ruleKey, 0, len(ruleMap))
		for key := range ruleMap {
			keys = append(keys, key)
		}
		slices.SortStableFunc(keys, func(a, b ruleKey) int {
			return strings.Compare(a.String(), b.String())
		})

		// Normalize rule verbs to "*" if any verb in the rule is an asterisk
		for _, rule := range ruleMap {
			if slices.Contains(rule.Verbs, "*") {
				rule.Verbs = []string{"*"}
			}
		}
		policyRules := make([]rbacv1.PolicyRule, 0, len(keys))
		for _, key := range keys {
			policyRules = append(policyRules, ruleMap[key].ToRule())
		}
		return policyRules
	}

	// collect all the namespace:roleName keys and sort them for stable output
	keys := make([]nsRoleKey, 0, len(rulesByNSRole))
	for key := range rulesByNSRole {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b nsRoleKey) int {
		// Sort by namespace first, then by roleName
		if a.namespace != b.namespace {
			return strings.Compare(a.namespace, b.namespace)
		}
		return strings.Compare(a.roleName, b.roleName)
	})

	// process the items in rulesByNSRole by the sorted order to make sure the output is stable
	var objs []any
	for _, key := range keys {
		rules := rulesByNSRole[key]
		policyRules := NormalizeRules(rules)
		if len(policyRules) == 0 {
			continue
		}
		if key.namespace == "" {
			objs = append(objs, rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: rbacv1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: key.roleName,
				},
				Rules: policyRules,
			})
		} else {
			objs = append(objs, rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: rbacv1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.roleName,
					Namespace: key.namespace,
				},
				Rules: policyRules,
			})
		}
	}

	return objs, nil
}

func (g Generator) Generate(ctx *genall.GenerationContext) error {
	objs, err := GenerateRoles(ctx, g.RoleName)
	if err != nil {
		return err
	}

	if len(objs) == 0 {
		return nil
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

	fileName := "role.yaml"
	if g.FileName != "" {
		fileName = g.FileName
	}

	return ctx.WriteYAML(fileName, headerText, objs, genall.WithTransform(genall.TransformRemoveCreationTimestamp))
}

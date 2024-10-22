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
	"sort"
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
type Rule struct {
	// Groups specifies the API groups that this rule encompasses.
	Groups []string `marker:",optional"`
	// Resources specifies the API resources that this rule encompasses.
	Resources []string `marker:",optional"`
	// ResourceNames specifies the names of the API resources that this rule encompasses.
	//
	// Create requests cannot be restricted by resourcename, as the object's name
	// is not known at authorization time.
	ResourceNames []string `marker:",optional"`
	// Verbs specifies the (lowercase) kubernetes API verbs that this rule encompasses.
	Verbs []string
	// URL specifies the non-resource URLs that this rule encompasses.
	URLs []string `marker:"urls,optional"`
	// Namespace specifies the scope of the Rule.
	// If not set, the Rule belongs to the generated ClusterRole.
	// If set, the Rule belongs to a Role, whose namespace is specified by this field.
	Namespace string `marker:",optional"`
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

// ruleKeys implements sort.Interface
type ruleKeys []ruleKey

func (keys ruleKeys) Len() int           { return len(keys) }
func (keys ruleKeys) Swap(i, j int)      { keys[i], keys[j] = keys[j], keys[i] }
func (keys ruleKeys) Less(i, j int) bool { return keys[i].String() < keys[j].String() }

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
	set := make(map[string]bool)
	for _, str := range strs {
		if _, ok := set[str]; !ok {
			set[str] = true
		}
	}

	var result []string
	for str := range set {
		result = append(result, str)
	}
	sort.Strings(result)
	return result
}

// ToRule converts this rule to its Kubernetes API form.
func (r *Rule) ToRule() rbacv1.PolicyRule {
	// fix the group names first, since letting people type "core" is nice
	for i, group := range r.Groups {
		if group == "core" {
			r.Groups[i] = ""
		}
	}
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
func GenerateRoles(ctx *genall.GenerationContext, roleName string) ([]interface{}, error) {
	rulesByNSResource := make(map[string][]*Rule)
	for _, root := range ctx.Roots {
		markerSet, err := markers.PackageMarkers(ctx.Collector, root)
		if err != nil {
			root.AddError(err)
		}

		// group RBAC markers by namespace and separate by resource
		for _, markerValue := range markerSet[RuleDefinition.Name] {
			rule := markerValue.(Rule)
			for _, resource := range rule.Resources {
				r := Rule{
					Groups:        rule.Groups,
					Resources:     []string{resource},
					ResourceNames: rule.ResourceNames,
					URLs:          rule.URLs,
					Namespace:     rule.Namespace,
					Verbs:         rule.Verbs,
				}
				namespace := r.Namespace
				rulesByNSResource[namespace] = append(rulesByNSResource[namespace], &r)
			}
		}
	}

	// NormalizeRules merge Rule with the same ruleKey and sort the Rules
	NormalizeRules := func(rules []*Rule) []rbacv1.PolicyRule {
		ruleMap := make(map[ruleKey]*Rule)
		// all the Rules having the same ruleKey will be merged into the first Rule
		for _, rule := range rules {
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

		// sort the Rules in rules according to their ruleKeys
		keys := make([]ruleKey, 0, len(ruleMap))
		for key := range ruleMap {
			keys = append(keys, key)
		}
		sort.Sort(ruleKeys(keys))

		var policyRules []rbacv1.PolicyRule
		for _, key := range keys {
			policyRules = append(policyRules, ruleMap[key].ToRule())
		}
		return policyRules
	}

	// collect all the namespaces and sort them
	var namespaces []string
	for ns := range rulesByNSResource {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	// process the items in rulesByNS by the order specified in `namespaces` to make sure that the Role order is stable
	var objs []interface{}
	for _, ns := range namespaces {
		rules := rulesByNSResource[ns]
		policyRules := NormalizeRules(rules)
		if len(policyRules) == 0 {
			continue
		}
		if ns == "" {
			objs = append(objs, rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: rbacv1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: roleName,
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
					Name:      roleName,
					Namespace: ns,
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

	return ctx.WriteYAML("role.yaml", headerText, objs, genall.WithTransform(genall.TransformRemoveCreationTimestamp))
}

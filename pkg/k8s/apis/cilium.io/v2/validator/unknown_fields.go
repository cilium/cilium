// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package validator

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jeremywohl/flatten"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// detectUnknownFields will check the given policy against the expected policy
// for any unknown fields that were found. The expected policy is retrieved by
// taking the given policy, marshalling it into its Golang type (CNP or CCNP),
// and unmarshalling it back into bytes. We can rely on this process to strip
// away "unknown" fields (specifically, fields that don't have a `json:...`
// annotation), hence it is expected. Once it's in bytes, we convert it to an
// unstructured.Unstructured type so that it matches with the given policy. A
// diff is performed between the two to uncover any differences.
//
// Special treatment is given if a top-level description field is found, and
// returns ErrTopLevelDescriptionFound if so. This is likely to be the most
// common path of this function as we can usually rely on the validation of the
// CRDs themselves, however the top-level description field has been widely
// used incorrectly (see https://github.com/cilium/cilium/issues/13155).
//
// This function returns the following possible errors:
//   - ErrTopLevelDescriptionFound
//   - ErrUnknownFields
//   - ErrUnknownKind
//   - Other marshalling / unmarshalling errors
func detectUnknownFields(policy *unstructured.Unstructured) error {
	kind := policy.GetKind()

	scopedLog := log
	switch kind {
	case cilium_v2.CNPKindDefinition:
		scopedLog = scopedLog.WithField(logfields.CiliumNetworkPolicyName,
			policy.GetName())
	case cilium_v2.CCNPKindDefinition:
		scopedLog = scopedLog.WithField(logfields.CiliumClusterwideNetworkPolicyName,
			policy.GetName())
	default:
		return ErrUnknownKind{
			kind: kind,
		}
	}

	if _, ok := policy.Object["description"]; ok {
		scopedLog.Warn(warnTopLevelDescriptionField)
		return ErrTopLevelDescriptionFound
	}

	policyBytes, err := policy.MarshalJSON()
	if err != nil {
		return err
	}

	var filtered map[string]interface{}
	switch kind {
	case cilium_v2.CNPKindDefinition:
		cnp := new(cilium_v2.CiliumNetworkPolicy)
		if err := json.Unmarshal(policyBytes, cnp); err != nil {
			return err
		}
		filtered, err = runtime.DefaultUnstructuredConverter.ToUnstructured(cnp)
	case cilium_v2.CCNPKindDefinition:
		ccnp := new(cilium_v2.CiliumClusterwideNetworkPolicy)
		if err := json.Unmarshal(policyBytes, ccnp); err != nil {
			return err
		}
		filtered, err = runtime.DefaultUnstructuredConverter.ToUnstructured(ccnp)
	default:
		// We've already validated above that there can only be two kinds: CNP
		// & CCNP. This is likely to be a developer error if hit, so fatal.
		scopedLog.WithField("kind", kind).Fatal("Unexpected kind found when processing policy")
	}
	if err != nil {
		return err
	}

	given, err := getFields(policy.Object)
	if err != nil {
		return err
	}

	expected, err := getFields(filtered)
	if err != nil {
		return err
	}

	// Compare the expected policy with the given policy to find all unknown
	// fields.
	var r reporter
	if !cmp.Equal(
		expected,
		given,
		cmp.Reporter(&r),
		cmpopts.SortSlices(func(o, n string) bool {
			return o < n
		}),
	) {
		scopedLog.Warn(warnUnknownFields)
		return ErrUnknownFields{
			extras: r.extras,
		}
	}

	return nil
}

const (
	warnTopLevelDescriptionField = "It seems you have a policy with a " +
		"top-level description. This field is no longer supported. Please migrate " +
		"your policy's description field under `spec` or `specs`."

	warnUnknownFields = "It seems you have a policy with extra unknown fields. " +
		"Consider removing these fields, as they have no effect. The presence " +
		"of these fields may have introduced a false sense security, so please " +
		"check whether your policy is actually behaving as you expect."
)

// ErrTopLevelDescriptionFound is the error returned if a policy contains a
// top-level description field. Instead this field should be moved to under
// (Rule).Description.
var ErrTopLevelDescriptionFound = errors.New("top-level description field found")

// ErrUnknownFields is an error representing the condition where unknown fields
// were found within a policy during validation. Fields that are not expected
// to be in the policy will be put inside the "extras" slice.
type ErrUnknownFields struct {
	extras []string
}

func (e ErrUnknownFields) Error() string {
	return fmt.Sprintf("unknown fields found, extra:%v", e.extras)
}

// ErrUnknownKind is an error representing an unknown Kubernetes object kind
// that is passed to the validator.
type ErrUnknownKind struct {
	kind string
}

func (e ErrUnknownKind) Error() string {
	return fmt.Sprintf("unknown kind %q", e.kind)
}

func getFields(u map[string]interface{}) ([]string, error) {
	flat, err := flattenObject(u)
	if err != nil {
		return nil, err
	}

	// set is used as a lookup for whether we've already seen the field path.
	// This is useful to dedup entries that match the "matchLabels" or
	// "matchExpressions" field path. Without this lookup, we will return a
	// slice containing duplicate entries. See example below.
	//   {
	//     "spec": {
	//       "endpointSelector": {
	//         "matchLabels": {
	//           "app": "",
	//           "key": "",
	//           "operator": ""
	//         }
	//       }
	//     }
	//   }
	// => []string{"spec.endpointSelector.matchLabels",
	//             "spec.endpointSelector.matchLabels",
	//             "spec.endpointSelector.matchLabels"}
	// Here we get an entry for each label inside "matchLabels". What we want
	// is []string{"spec.endpointSelector.matchLabels"}. See comment inside the
	// for-loop below for why we have to truncate the labels.
	set := make(map[string]struct{})

	fields := make([]string, 0, len(flat))
	for f := range flat {
		// Due to converting to Unstructured (same issue as ignoring fields
		// below), we need to truncate any label under "matchLabels" or
		// "matchExpressions", to effectively ignore the labels. This is
		// because they are arbitrary as the user can specify anything they
		// want. We will strip off the label, and keep the entire field path up
		// to and including "matchLabels" or "matchExpressions", which we
		// insert to the "fields" slice.
		if matches := arbitraryLabelRegex.FindStringSubmatch(f); len(matches) > 1 {
			m := matches[1] // matches[0] contains the full match

			if _, seen := set[m]; !seen {
				set[m] = struct{}{} // Mark as seen
				fields = append(fields, m)
			}
		} else if !isIgnoredField(f) {
			fields = append(fields, f)
		}
	}

	return fields, nil
}

// arbitraryLabelRegex matches any field path that includes "matchLabels" or
// "matchExpressions". For example, it matches the following:
//   - spec.endpointSelector.matchLabels.*
//   - specs.0.ingress.0.fromEndpoints.0.matchLabels.*
//   - specs.0.ingress.0.fromEndpoints.0.matchExpressions.*
var arbitraryLabelRegex = regexp.MustCompile(`^(.+\.(matchLabels|matchExpressions))\..+$`)

func flattenObject(obj map[string]interface{}) (map[string]interface{}, error) {
	return flatten.Flatten(obj, "", flatten.DotStyle)
}

func isIgnoredField(f string) bool {
	// We ignore the creation timestamp and the name because when marshalling
	// and unmarshalling happens when converting to Unstructured, these fields
	// are added in the "expected" policy.  These fields missing should not be
	// warned about. Specifically for "metadata.name", a CRD cannot be created
	// without it, so in reality, we can rely on the CRD validation, hence it
	// is safe to ignore at this level of the code.
	return f == "metadata.creationTimestamp" || f == "metadata.name"
}

// reporter is a custom reporter adhering to the cmp.Reporter interface.
type reporter struct {
	path   cmp.Path
	extras []string
}

func (r *reporter) PushStep(ps cmp.PathStep) {
	r.path = append(r.path, ps)
}

func (r *reporter) Report(rs cmp.Result) {
	if !rs.Equal() {
		// The below call returns two values of the diff, vx & xy. In our case,
		// vx represents a "missing" value (-) in the diff, and vy represents
		// an "extra" value (+) in the diff. We ignore vx because it is not
		// possible to have "missing" values, because the validator will catch
		// "missing" or "required" values earlier on. We only care about
		// "extra" values here.
		_, vy := r.path.Last().Values()
		if vy.IsValid() {
			r.extras = append(r.extras, vy.String())
		}
	}
}

func (r *reporter) PopStep() {
	r.path = r.path[:len(r.path)-1]
}

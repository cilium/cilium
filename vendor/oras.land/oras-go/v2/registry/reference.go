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

package registry

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/errdef"
)

// regular expressions for components.
var (
	// repositoryRegexp is adapted from the distribution implementation. The
	// repository name set under OCI distribution spec is a subset of the docker
	// spec. For maximum compatability, the docker spec is verified client-side.
	// Further checks are left to the server-side.
	//
	// References:
	//   - https://github.com/distribution/distribution/blob/v2.7.1/reference/regexp.go#L53
	//   - https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests
	repositoryRegexp = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*)*$`)

	// tagRegexp checks the tag name.
	// The docker and OCI spec have the same regular expression.
	//
	// Reference: https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#pulling-manifests
	tagRegexp = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
)

// Reference references either a resource descriptor (where Reference.Reference
// is a tag or a digest), or a resource repository (where Reference.Reference
// is the empty string).
type Reference struct {
	// Registry is the name of the registry. It is usually the domain name of
	// the registry optionally with a port.
	Registry string

	// Repository is the name of the repository.
	Repository string

	// Reference is the reference of the object in the repository. This field
	// can take any one of the four valid forms (see ParseReference). In the
	// case where it's the empty string, it necessarily implies valid form D,
	// and where it is non-empty, then it is either a tag, or a digest
	// (implying one of valid forms A, B, or C).
	Reference string
}

// ParseReference parses a string (artifact) into an `artifact reference`.
// Corresponding cryptographic hash implementations are required to be imported
// as specified by https://pkg.go.dev/github.com/opencontainers/go-digest#readme-usage
// if the string contains a digest.
//
// Note: An "image" is an "artifact", however, an "artifact" is not necessarily
// an "image".
//
// The token `artifact` is composed of other tokens, and those in turn are
// composed of others.  This definition recursivity requires a notation capable
// of recursion, thus the following two forms have been adopted:
//
//  1. Backus–Naur Form (BNF) has been adopted to address the recursive nature
//     of the definition.
//  2. Token opacity is revealed via its label letter-casing.  That is, "opaque"
//     tokens (i.e., tokens that are not final, and must therefore be further
//     broken down into their constituents) are denoted in *lowercase*, while
//     final tokens (i.e., leaf-node tokens that are final) are denoted in
//     *uppercase*.
//
// Finally, note that a number of the opaque tokens are polymorphic in nature;
// that is, they can take on one of numerous forms, not restricted to a single
// defining form.
//
// The top-level token, `artifact`, is composed of two (opaque) tokens; namely
// `socketaddr` and `path`:
//
//	<artifact> ::= <socketaddr> "/" <path>
//
// The former is described as follows:
//
//	   <socketaddr> ::= <host> | <host> ":" <PORT>
//		     <host> ::= <ip> | <FQDN>
//		       <ip> ::= <IPV4-ADDR> | <IPV6-ADDR>
//
// The latter, which is of greater interest here, is described as follows:
//
//	     <path> ::= <REPOSITORY> | <REPOSITORY> <reference>
//	<reference> ::= "@" <digest> | ":" <TAG> "@" <DIGEST> | ":" <TAG>
//	   <digest> ::= <ALGO> ":" <HASH>
//
// This second token--`path`--can take on exactly four forms, each of which will
// now be illustrated:
//
//	<--- path --------------------------------------------> |  - Decode `path`
//	<=== REPOSITORY ===> <--- reference ------------------> |    - Decode `reference`
//	<=== REPOSITORY ===> @ <=================== digest ===> |      - Valid Form A
//	<=== REPOSITORY ===> : <!!! TAG !!!> @ <=== digest ===> |      - Valid Form B (tag is dropped)
//	<=== REPOSITORY ===> : <=== TAG ======================> |      - Valid Form C
//	<=== REPOSITORY ======================================> |    - Valid Form D
//
// Note: In the case of Valid Form B, TAG is dropped without any validation or
// further consideration.
func ParseReference(artifact string) (Reference, error) {
	parts := strings.SplitN(artifact, "/", 2)
	if len(parts) == 1 {
		// Invalid Form
		return Reference{}, fmt.Errorf("%w: missing registry or repository", errdef.ErrInvalidReference)
	}
	registry, path := parts[0], parts[1]

	var isTag bool
	var repository string
	var reference string
	if index := strings.Index(path, "@"); index != -1 {
		// `digest` found; Valid Form A (if not B)
		isTag = false
		repository = path[:index]
		reference = path[index+1:]

		if index = strings.Index(repository, ":"); index != -1 {
			// `tag` found (and now dropped without validation) since `the
			// `digest` already present; Valid Form B
			repository = repository[:index]
		}
	} else if index = strings.Index(path, ":"); index != -1 {
		// `tag` found; Valid Form C
		isTag = true
		repository = path[:index]
		reference = path[index+1:]
	} else {
		// empty `reference`; Valid Form D
		repository = path
	}
	ref := Reference{
		Registry:   registry,
		Repository: repository,
		Reference:  reference,
	}

	if err := ref.ValidateRegistry(); err != nil {
		return Reference{}, err
	}

	if err := ref.ValidateRepository(); err != nil {
		return Reference{}, err
	}

	if len(ref.Reference) == 0 {
		return ref, nil
	}

	validator := ref.ValidateReferenceAsDigest
	if isTag {
		validator = ref.ValidateReferenceAsTag
	}
	if err := validator(); err != nil {
		return Reference{}, err
	}

	return ref, nil
}

// Validate the entire reference object; the registry, the repository, and the
// reference.
func (r Reference) Validate() error {
	if err := r.ValidateRegistry(); err != nil {
		return err
	}

	if err := r.ValidateRepository(); err != nil {
		return err
	}

	return r.ValidateReference()
}

// ValidateRegistry validates the registry.
func (r Reference) ValidateRegistry() error {
	if uri, err := url.ParseRequestURI("dummy://" + r.Registry); err != nil || uri.Host == "" || uri.Host != r.Registry {
		return fmt.Errorf("%w: invalid registry %q", errdef.ErrInvalidReference, r.Registry)
	}
	return nil
}

// ValidateRepository validates the repository.
func (r Reference) ValidateRepository() error {
	if !repositoryRegexp.MatchString(r.Repository) {
		return fmt.Errorf("%w: invalid repository %q", errdef.ErrInvalidReference, r.Repository)
	}
	return nil
}

// ValidateReferenceAsTag validates the reference as a tag.
func (r Reference) ValidateReferenceAsTag() error {
	if !tagRegexp.MatchString(r.Reference) {
		return fmt.Errorf("%w: invalid tag %q", errdef.ErrInvalidReference, r.Reference)
	}
	return nil
}

// ValidateReferenceAsDigest validates the reference as a digest.
func (r Reference) ValidateReferenceAsDigest() error {
	if _, err := r.Digest(); err != nil {
		return fmt.Errorf("%w: invalid digest %q: %v", errdef.ErrInvalidReference, r.Reference, err)
	}
	return nil
}

// ValidateReference where the reference is first tried as an ampty string, then
// as a digest, and if that fails, as a tag.
func (r Reference) ValidateReference() error {
	if len(r.Reference) == 0 {
		return nil
	}

	if index := strings.IndexByte(r.Reference, ':'); index != -1 {
		return r.ValidateReferenceAsDigest()
	}

	return r.ValidateReferenceAsTag()
}

// Host returns the host name of the registry.
func (r Reference) Host() string {
	if r.Registry == "docker.io" {
		return "registry-1.docker.io"
	}
	return r.Registry
}

// ReferenceOrDefault returns the reference or the default reference if empty.
func (r Reference) ReferenceOrDefault() string {
	if r.Reference == "" {
		return "latest"
	}
	return r.Reference
}

// Digest returns the reference as a digest.
// Corresponding cryptographic hash implementations are required to be imported
// as specified by https://pkg.go.dev/github.com/opencontainers/go-digest#readme-usage
func (r Reference) Digest() (digest.Digest, error) {
	return digest.Parse(r.Reference)
}

// String implements `fmt.Stringer` and returns the reference string.
// The resulted string is meaningful only if the reference is valid.
func (r Reference) String() string {
	if r.Repository == "" {
		return r.Registry
	}
	ref := r.Registry + "/" + r.Repository
	if r.Reference == "" {
		return ref
	}
	if d, err := r.Digest(); err == nil {
		return ref + "@" + d.String()
	}
	return ref + ":" + r.Reference
}

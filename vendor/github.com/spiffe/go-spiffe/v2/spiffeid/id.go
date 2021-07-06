package spiffeid

import (
	"net/url"
	"path"
	"strings"

	"github.com/zeebo/errs"
)

var idErr = errs.Class("spiffeid")

// ID is a SPIFFE ID
type ID struct {
	td   TrustDomain
	path string
}

// New creates a new ID using the trust domain (e.g. example.org) and path
// segments. The resulting path after joining the segments is normalized according
// to the rules of the standard path.Join() function. An error is returned if the
// trust domain is not valid (see TrustDomainFromString).
func New(trustDomain string, segments ...string) (ID, error) {
	td, err := TrustDomainFromString(trustDomain)
	if err != nil {
		return ID{}, err
	}

	return ID{
		td:   td,
		path: normalizePath(path.Join(segments...)),
	}, nil
}

// Must creates a new ID using the trust domain (e.g. example.org) and path
// segments. The function panics if the trust domain is not valid (see
// TrustDomainFromString).
func Must(trustDomain string, segments ...string) ID {
	id, err := New(trustDomain, segments...)
	if err != nil {
		panic(err)
	}
	return id
}

// Join returns the string representation of an ID inside the given trust
// domain (e.g. example.org) with the given path segments. An error is returned
// if the trust domain is not valid (see TrustDomainFromString).
func Join(trustDomain string, segments ...string) (string, error) {
	id, err := New(trustDomain, segments...)
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

// MustJoin returns the string representation of an ID inside the given trust
// domain (e.g. example.org) with the given path segments. The function panics
// if the trust domain is not valid (see TrustDomainFromString).
func MustJoin(trustDomain string, segments ...string) string {
	idstr, err := Join(trustDomain, segments...)
	if err != nil {
		panic(err)
	}
	return idstr
}

// FromString parses a SPIFFE ID from a string.
func FromString(s string) (ID, error) {
	uri, err := url.Parse(s)
	if err != nil {
		return ID{}, idErr.New("unable to parse: %w", err)
	}

	return FromURI(uri)
}

// FromURI parses a SPIFFE ID from a URI.
func FromURI(uri *url.URL) (ID, error) {
	// General validation
	switch {
	case uri == nil:
		return ID{}, idErr.New("ID is nil")
	case *uri == (url.URL{}):
		return ID{}, idErr.New("ID is empty")
	case strings.ToLower(uri.Scheme) != "spiffe":
		return ID{}, idErr.New("invalid scheme")
	case uri.User != nil:
		return ID{}, idErr.New("user info is not allowed")
	case uri.Host == "":
		return ID{}, idErr.New("trust domain is empty")
	case uri.Port() != "":
		return ID{}, idErr.New("port is not allowed")
	case strings.Contains(uri.Host, ":"):
		return ID{}, idErr.New("colon is not allowed in trust domain")
	case uri.Fragment != "":
		return ID{}, idErr.New("fragment is not allowed")
	case uri.RawQuery != "":
		return ID{}, idErr.New("query is not allowed")
	}

	return ID{
		td:   TrustDomain{name: normalizeTrustDomain(uri.Host)},
		path: uri.Path,
	}, nil
}

// RequireFromString is similar to FromString except that instead of returning
// an error on malformed input, it panics. It should only be used when given
// string is statically verifiable.
func RequireFromString(s string) ID {
	id, err := FromString(s)
	if err != nil {
		panic(err)
	}
	return id
}

// RequireFromURI is similar to FromURI except that instead of returning
// an error on malformed input, it panics. It should only be used when given
// string is statically verifiable.
func RequireFromURI(uri *url.URL) ID {
	id, err := FromURI(uri)
	if err != nil {
		panic(err)
	}
	return id
}

// TrustDomain returns the trust domain of the SPIFFE ID.
func (id ID) TrustDomain() TrustDomain {
	return id.td
}

// MemberOf returns true if the SPIFFE ID is a member of the given trust domain.
func (id ID) MemberOf(td TrustDomain) bool {
	return id.td == td
}

// Path returns the path of the SPIFFE ID inside the trust domain.
func (id ID) Path() string {
	return id.path
}

// String returns the string representation of the SPIFFE ID, e.g.,
// "spiffe://example.org/foo/bar".
func (id ID) String() string {
	if id.IsZero() {
		return ""
	}

	return id.URL().String()
}

// URL returns a URL for SPIFFE ID.
func (id ID) URL() *url.URL {
	if id.IsZero() {
		return &url.URL{}
	}

	return &url.URL{
		Scheme: "spiffe",
		Host:   id.td.name,
		Path:   id.path,
	}
}

// IsZero returns true if the SPIFFE ID is the zero value.
func (id ID) IsZero() bool {
	return id.td.IsZero()
}

func normalizeTrustDomain(td string) string {
	return strings.ToLower(td)
}

func normalizePath(path string) string {
	if len(path) > 0 && path[0] != '/' {
		return "/" + path
	}

	return path
}

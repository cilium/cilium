package spiffeid

import (
	"net/url"
	"strings"
)

// TrustDomain is the name of a SPIFFE trust domain (e.g. example.org).
type TrustDomain struct {
	name string
}

// TrustDomainFromString returns a new TrustDomain from a string. The string
// can either be the host part of a URI authority component (e.g. example.org),
// or a valid SPIFFE ID URI (e.g. spiffe://example.org), otherwise an error is
// returned.  The trust domain is normalized to lower case.
func TrustDomainFromString(s string) (TrustDomain, error) {
	if !strings.Contains(s, "://") {
		s = "spiffe://" + s
	}

	id, err := FromString(s)
	if err != nil {
		return TrustDomain{}, err
	}

	return id.td, nil
}

// RequireTrustDomainFromString is similar to TrustDomainFromString except that
// instead of returning an error on malformed input, it panics. It should only
// be used when given string is statically verifiable.
func RequireTrustDomainFromString(s string) TrustDomain {
	td, err := TrustDomainFromString(s)
	if err != nil {
		panic(err)
	}
	return td
}

// TrustDomainFromURI returns a new TrustDomain from a URI. The URI must be a
// valid SPIFFE ID (see FromURI) or an error is returned. The trust domain is
// extracted from the host field and normalized to lower case.
func TrustDomainFromURI(uri *url.URL) (TrustDomain, error) {
	id, err := FromURI(uri)
	if err != nil {
		return TrustDomain{}, err
	}

	return id.TrustDomain(), nil
}

// RequireTrustDomainFromURI is similar to TrustDomainFromURI except that
// instead of returning an error on malformed input, it panics. It should only
// be used when the given URI is statically verifiable.
func RequireTrustDomainFromURI(uri *url.URL) TrustDomain {
	td, err := TrustDomainFromURI(uri)
	if err != nil {
		panic(err)
	}
	return td
}

// String returns the trust domain as a string, e.g. example.org.
func (td TrustDomain) String() string {
	return td.name
}

// ID returns the SPIFFE ID of the trust domain.
func (td TrustDomain) ID() ID {
	return ID{
		td:   td,
		path: "",
	}
}

// IDString returns a string representation of the the SPIFFE ID of the trust domain,
// e.g. "spiffe://example.org".
func (td TrustDomain) IDString() string {
	return td.ID().String()
}

// NewID returns a SPIFFE ID with the given path inside the trust domain.
func (td TrustDomain) NewID(path string) ID {
	return ID{
		td:   td,
		path: normalizePath(path),
	}
}

// IsZero returns true if the trust domain is the zero value.
func (td TrustDomain) IsZero() bool {
	return td.name == ""
}

// Compare returns an integer comparing the trust domain to another
// lexicographically. The result will be 0 if td==other, -1 if td < other, and
// +1 if td > other.
func (td TrustDomain) Compare(other TrustDomain) int {
	return strings.Compare(td.name, other.name)
}

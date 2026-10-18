package tlsconfig

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Authorizer authorizes an X509-SVID given the SPIFFE ID and the chain
// of trust. The certificate chain starts with the X509-SVID certificate back
// to an X.509 root for the trust domain.
type Authorizer func(id spiffeid.ID, verifiedChains [][]*x509.Certificate) error

// AuthorizeAny allows any SPIFFE ID.
func AuthorizeAny() Authorizer {
	return AdaptMatcher(spiffeid.MatchAny())
}

// AuthorizeID allows a specific SPIFFE ID.
func AuthorizeID(allowed spiffeid.ID) Authorizer {
	return AdaptMatcher(spiffeid.MatchID(allowed))
}

// AuthorizeIDPrefix allows any SPIFFE ID with the given ID prefix. A matching
// ID must be in the same trust domain and have either the same path as the
// prefix or a path with the prefix on a segment boundary. If the prefix has no
// path, no ID is authorized.
func AuthorizeIDPrefix(allowed spiffeid.ID) Authorizer {
	return AdaptMatcher(spiffeid.MatchIDPrefix(allowed))
}

// AuthorizeOneOf allows any SPIFFE ID in the given list of IDs.
func AuthorizeOneOf(allowed ...spiffeid.ID) Authorizer {
	return AdaptMatcher(spiffeid.MatchOneOf(allowed...))
}

// AuthorizeMemberOf allows any SPIFFE ID in the given trust domain.
func AuthorizeMemberOf(allowed spiffeid.TrustDomain) Authorizer {
	return AdaptMatcher(spiffeid.MatchMemberOf(allowed))
}

// AdaptMatcher adapts any spiffeid.Matcher for use as an Authorizer which
// only authorizes the SPIFFE ID but otherwise ignores the verified chains.
func AdaptMatcher(matcher spiffeid.Matcher) Authorizer {
	return Authorizer(func(actual spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
		return matcher(actual)
	})
}

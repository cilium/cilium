package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// X509Context conveys X.509 materials from the Workload API.
type X509Context struct {
	// SVIDs is a list of workload X509-SVIDs.
	SVIDs []*x509svid.SVID

	// Bundles is a set of X.509 bundles.
	Bundles *x509bundle.Set
}

// Default returns the default X509-SVID (the first in the list).
//
// See the SPIFFE Workload API standard Section 5.3.
// (https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md#53-default-identity)
func (x *X509Context) DefaultSVID() *x509svid.SVID {
	return x.SVIDs[0]
}

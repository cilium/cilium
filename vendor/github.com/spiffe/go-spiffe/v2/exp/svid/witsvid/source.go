package witsvid

import "github.com/spiffe/go-spiffe/v2/spiffeid"

// Source is a source of WIT-SVIDs keyed by SPIFFE ID.
type Source interface {
	// GetWITSVIDForID returns the WIT-SVID for the given SPIFFE ID.
	GetWITSVIDForID(id spiffeid.ID) (*SVID, error)
}

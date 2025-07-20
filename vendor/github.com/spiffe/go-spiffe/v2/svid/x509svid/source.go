package x509svid

// Source represents a source of X509-SVIDs.
type Source interface {
	// GetX509SVID returns an X509-SVID from the source.
	GetX509SVID() (*SVID, error)
}

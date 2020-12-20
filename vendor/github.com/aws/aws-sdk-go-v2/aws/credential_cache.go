package aws

import (
	"context"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/internal/sync/singleflight"
)

// CredentialsCache provides caching and concurrency safe credentials retrieval
// via the provider's retrieve method.
type CredentialsCache struct {
	Provider CredentialsProvider

	creds atomic.Value
	sf    singleflight.Group
}

// Retrieve returns the credentials. If the credentials have already been
// retrieved, and not expired the cached credentials will be returned. If the
// credentials have not been retrieved yet, or expired the provider's Retrieve
// method will be called.
//
// Returns and error if the provider's retrieve method returns an error.
func (p *CredentialsCache) Retrieve(ctx context.Context) (Credentials, error) {
	if creds := p.getCreds(); creds != nil {
		return *creds, nil
	}

	resCh := p.sf.DoChan("", p.singleRetrieve)
	select {
	case res := <-resCh:
		return res.Val.(Credentials), res.Err
	case <-ctx.Done():
		return Credentials{}, &RequestCanceledError{Err: ctx.Err()}
	}
}

func (p *CredentialsCache) singleRetrieve() (interface{}, error) {
	if creds := p.getCreds(); creds != nil {
		return *creds, nil
	}

	creds, err := p.Provider.Retrieve(context.TODO())
	if err == nil {
		p.creds.Store(&creds)
	}

	return creds, err
}

func (p *CredentialsCache) getCreds() *Credentials {
	v := p.creds.Load()
	if v == nil {
		return nil
	}

	c := v.(*Credentials)
	if c != nil && c.HasKeys() && !c.Expired() {
		return c
	}

	return nil
}

// Invalidate will invalidate the cached credentials. The next call to Retrieve
// will cause the provider's Retrieve method to be called.
func (p *CredentialsCache) Invalidate() {
	p.creds.Store((*Credentials)(nil))
}

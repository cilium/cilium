package aws

import (
	"context"
	"math"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/aws/aws-sdk-go-v2/internal/sync/singleflight"
)

// NeverExpire is the time identifier used when a credential provider's
// credentials will not expire. This is used in cases where a non-expiring
// provider type cannot be used.
var NeverExpire = time.Unix(math.MaxInt64, 0)

// AnonymousCredentials is an empty CredentialProvider that can be used as
// dummy placeholder credentials for requests that do not need signed.
//
// This credentials can be used to configure a service to not sign requests
// when making service API calls. For example, when accessing public
// s3 buckets.
//
//     s3Cfg := cfg.Copy()
//     s3cfg.Credentials = AnonymousCredentials
//
//     svc := s3.New(s3Cfg)
var AnonymousCredentials = StaticCredentialsProvider{
	Value: Credentials{Source: "AnonymousCredentials"},
}

// An Expiration provides wrapper around time with expiration related methods.
type Expiration time.Time

// Expired returns if the time has expired.

// A Credentials is the AWS credentials value for individual credential fields.
type Credentials struct {
	// AWS Access key ID
	AccessKeyID string

	// AWS Secret Access Key
	SecretAccessKey string

	// AWS Session Token
	SessionToken string

	// Source of the credentials
	Source string

	// Time the credentials will expire.
	CanExpire bool
	Expires   time.Time
}

// Expired returns if the credetials have expired.
func (v Credentials) Expired() bool {
	if v.CanExpire {
		return !v.Expires.After(sdk.NowTime())
	}

	return false
}

// HasKeys returns if the credentials keys are set.
func (v Credentials) HasKeys() bool {
	return len(v.AccessKeyID) > 0 && len(v.SecretAccessKey) > 0
}

// A CredentialsProvider is the interface for any component which will provide credentials
// Credentials. A CredentialsProvider is required to manage its own Expired state, and what to
// be expired means.
//
// The CredentialsProvider should not need to implement its own mutexes, because
// that will be managed by CredentialsLoader.
type CredentialsProvider interface {
	// Retrieve returns nil if it successfully retrieved the value.
	// Error is returned if the value were not obtainable, or empty.
	Retrieve(ctx context.Context) (Credentials, error)
}

// SafeCredentialsProvider provides caching and concurrency safe credentials
// retrieval via the RetrieveFn.
type SafeCredentialsProvider struct {
	RetrieveFn func() (Credentials, error)

	creds atomic.Value
	sf    singleflight.Group
}

// Retrieve returns the credentials. If the credentials have already been
// retrieved, and not expired the cached credentials will be returned. If the
// credentials have not been retrieved yet, or expired RetrieveFn will be called.
//
// Returns and error if RetrieveFn returns an error.
func (p *SafeCredentialsProvider) Retrieve(ctx context.Context) (Credentials, error) {
	if creds := p.getCreds(); creds != nil {
		return *creds, nil
	}

	resCh := p.sf.DoChan("", p.singleRetrieve)
	select {
	case res := <-resCh:
		return res.Val.(Credentials), res.Err
	case <-ctx.Done():
		return Credentials{}, awserr.New("RequestCanceled",
			"request context canceled", ctx.Err())
	}
}

func (p *SafeCredentialsProvider) singleRetrieve() (interface{}, error) {
	if creds := p.getCreds(); creds != nil {
		return *creds, nil
	}

	creds, err := p.RetrieveFn()
	if err == nil {
		p.creds.Store(&creds)
	}

	return creds, err
}

func (p *SafeCredentialsProvider) getCreds() *Credentials {
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
// will cause RetrieveFn to be called.
func (p *SafeCredentialsProvider) Invalidate() {
	p.creds.Store((*Credentials)(nil))
}

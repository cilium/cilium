package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
)

// StaticCredentialsProviderName provides a name of Static provider
const StaticCredentialsProviderName = "StaticCredentialsProvider"

var (
	// ErrStaticCredentialsEmpty is emitted when static credentials are empty.
	ErrStaticCredentialsEmpty = awserr.New("EmptyStaticCreds", "static credentials are empty", nil)
)

// A StaticCredentialsProvider is a set of credentials which are set programmatically,
// and will never expire.
type StaticCredentialsProvider struct {
	Value Credentials
}

// NewStaticCredentialsProvider return a StaticCredentialsProvider initialized with the AWS credentials
// passed in.
func NewStaticCredentialsProvider(key, secret, session string) StaticCredentialsProvider {
	return StaticCredentialsProvider{
		Value: Credentials{
			AccessKeyID:     key,
			SecretAccessKey: secret,
			SessionToken:    session,
		},
	}
}

// Retrieve returns the credentials or error if the credentials are invalid.
func (s StaticCredentialsProvider) Retrieve() (Credentials, error) {
	v := s.Value
	if v.AccessKeyID == "" || v.SecretAccessKey == "" {
		return Credentials{Source: StaticCredentialsProviderName}, ErrStaticCredentialsEmpty
	}

	if len(v.Source) == 0 {
		v.Source = StaticCredentialsProviderName
	}

	return v, nil
}

// IsExpired returns if the credentials are expired.
//
// For StaticCredentialsProvider, the credentials never expired.
func (s StaticCredentialsProvider) IsExpired() bool {
	return false
}

package aws

import (
	"context"
)

const (
	// StaticCredentialsProviderName provides a name of Static provider
	StaticCredentialsProviderName = "StaticCredentialsProvider"
)

// StaticCredentialsEmptyError is emitted when static credentials are empty.
type StaticCredentialsEmptyError struct{}

func (*StaticCredentialsEmptyError) Error() string {
	return "static credentials are empty"
}

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
func (s StaticCredentialsProvider) Retrieve(_ context.Context) (Credentials, error) {
	v := s.Value
	if v.AccessKeyID == "" || v.SecretAccessKey == "" {
		return Credentials{Source: StaticCredentialsProviderName}, &StaticCredentialsEmptyError{}
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

package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
)

// A ChainProvider will search for a provider which returns credentials
// and cache that provider until Retrieve is called again.
//
// The ChainProvider provides a way of chaining multiple providers together
// which will pick the first available using priority order of the Providers
// in the list.
//
// If none of the Providers retrieve valid credentials Credentials, ChainProvider's
// Retrieve() will return the error ErrNoValidProvidersFoundInChain.
//
// If a CredentialsProvider is found which returns valid credentials Credentials ChainProvider
// will cache that CredentialsProvider for all calls to IsExpired(), until Retrieve is
// called again.
//
// Example of ChainProvider to be used with an EnvProvider and EC2RoleProvider.
// In this example EnvProvider will first check if any credentials are available
// via the environment variables. If there are none ChainProvider will check
// the next CredentialsProvider in the list, EC2RoleProvider in this case. If EC2RoleProvider
// does not return any credentials ChainProvider will return the error
// ErrNoValidProvidersFoundInChain
//
//     creds := aws.NewChainCredentials(
//         []aws.CredentialsProvider{
//             &credentials.EnvProvider{},
//             &ec2rolecreds.EC2RoleProvider{
//                 Client: ec2metadata.New(cfg),
//             },
//         })
//
//     // Usage of ChainCredentials with aws.Config
//     cfg := cfg.Copy()
//     cfg.Credentials = creds
//     svc := ec2.New(cfg)
//
type ChainProvider struct {
	SafeCredentialsProvider

	Providers []CredentialsProvider
}

// NewChainProvider returns a pointer to a new ChainProvider value wrapping
// a chain of credentials providers.
func NewChainProvider(providers []CredentialsProvider) *ChainProvider {
	p := &ChainProvider{
		Providers: append([]CredentialsProvider{}, providers...),
	}
	p.RetrieveFn = p.retrieveFn

	return p
}

// Retrieve returns the credentials value or error if no provider returned
// without error.
//
// If a provider is found it will be cached and any calls to IsExpired()
// will return the expired state of the cached provider.
func (c *ChainProvider) retrieveFn() (Credentials, error) {
	var errs []error
	for _, p := range c.Providers {
		creds, err := p.Retrieve()
		if err == nil {
			return creds, nil
		}
		errs = append(errs, err)
	}

	return Credentials{},
		awserr.NewBatchError("NoCredentialProviders", "no valid providers in chain", errs)
}

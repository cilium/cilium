package external

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/aws/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/aws/processcreds"
	"github.com/aws/aws-sdk-go-v2/aws/stscreds"
)

// SharedConfigProfileProvider provides access to the shared config profile
// name external configuration value.
type SharedConfigProfileProvider interface {
	GetSharedConfigProfile() (string, error)
}

// WithSharedConfigProfile wraps a strings to satisfy the SharedConfigProfileProvider
// interface so a slice of custom shared config files ared used when loading the
// SharedConfig.
type WithSharedConfigProfile string

// GetSharedConfigProfile returns the shared config profile.
func (c WithSharedConfigProfile) GetSharedConfigProfile() (string, error) {
	return string(c), nil
}

// GetSharedConfigProfile searches the Configs for a SharedConfigProfileProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func GetSharedConfigProfile(configs Configs) (string, bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(SharedConfigProfileProvider); ok {
			v, err := p.GetSharedConfigProfile()
			if err != nil {
				return "", false, err
			}
			if len(v) > 0 {
				return v, true, nil
			}
		}
	}

	return "", false, nil
}

// SharedConfigFilesProvider provides access to the shared config filesnames
// external configuration value.
type SharedConfigFilesProvider interface {
	GetSharedConfigFiles() ([]string, error)
}

// WithSharedConfigFiles wraps a slice of strings to satisfy the
// SharedConfigFilesProvider interface so a slice of custom shared config files
// ared used when loading the SharedConfig.
type WithSharedConfigFiles []string

// GetSharedConfigFiles returns the slice of shared config files.
func (c WithSharedConfigFiles) GetSharedConfigFiles() ([]string, error) {
	return []string(c), nil
}

// GetSharedConfigFiles searchds the Configs for a SharedConfigFilesProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func GetSharedConfigFiles(configs Configs) ([]string, bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(SharedConfigFilesProvider); ok {
			v, err := p.GetSharedConfigFiles()
			if err != nil {
				return nil, false, err
			}
			if len(v) > 0 {
				return v, true, nil
			}
		}
	}

	return nil, false, nil
}

// CustomCABundleProvider provides access to the custom CA bundle PEM bytes.
type CustomCABundleProvider interface {
	GetCustomCABundle() ([]byte, error)
}

// WithCustomCABundle provides wrapping of a region string to satisfy the
// CustomCABundleProvider interface.
type WithCustomCABundle []byte

// GetCustomCABundle returns the CA bundle PEM bytes.
func (v WithCustomCABundle) GetCustomCABundle() ([]byte, error) {
	return []byte(v), nil
}

// GetCustomCABundle searchds the Configs for a CustomCABundleProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func GetCustomCABundle(configs Configs) ([]byte, bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(CustomCABundleProvider); ok {
			v, err := p.GetCustomCABundle()
			if err != nil {
				return nil, false, err
			}
			if len(v) > 0 {
				return v, true, nil
			}
		}
	}

	return nil, false, nil
}

// RegionProvider provides access to the region external configuration value.
type RegionProvider interface {
	GetRegion() (string, error)
}

// WithRegion provides wrapping of a region string to satisfy the RegionProvider
// interface.
type WithRegion string

// GetRegion returns the region string.
func (v WithRegion) GetRegion() (string, error) {
	return string(v), nil
}

// GetRegion searchds the Configs for a RegionProvider and returns the value
// if found. Returns an error if a provider fails before a value is found.
func GetRegion(configs Configs) (string, bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(RegionProvider); ok {
			v, err := p.GetRegion()
			if err != nil {
				return "", false, err
			}
			if len(v) > 0 {
				return v, true, nil
			}
		}
	}

	return "", false, nil
}

// CredentialsProviderProvider provides access to the credentials external
// configuration value.
type CredentialsProviderProvider interface {
	GetCredentialsProvider() (aws.CredentialsProvider, bool, error)
}

// WithCredentialsProvider provides wrapping of a credentials Value to satisfy the
// CredentialsProviderProvider interface.
type WithCredentialsProvider struct {
	aws.CredentialsProvider
}

// GetCredentialsProvider returns the credentials value.
func (v WithCredentialsProvider) GetCredentialsProvider() (aws.CredentialsProvider, bool, error) {
	if v.CredentialsProvider == nil {
		return nil, false, nil
	}

	return v.CredentialsProvider, true, nil
}

// GetCredentialsProvider searches the Configs for a CredentialsProviderProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func GetCredentialsProvider(configs Configs) (p aws.CredentialsProvider, found bool, err error) {
	for _, cfg := range configs {
		if provider, ok := cfg.(CredentialsProviderProvider); ok {
			p, found, err = provider.GetCredentialsProvider()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}

	return p, found, err
}

// MFATokenFuncProvider provides access to the MFA token function needed for
// Assume Role with MFA.
type MFATokenFuncProvider interface {
	GetMFATokenFunc() (func() (string, error), error)
}

// WithMFATokenFunc provides wrapping of a string to satisfy the
// MFATokenFuncProvider interface.
type WithMFATokenFunc func() (string, error)

// GetMFATokenFunc returns the MFA Token function.
func (p WithMFATokenFunc) GetMFATokenFunc() (func() (string, error), error) {
	return p, nil
}

// GetMFATokenFunc searches the Configs for a MFATokenFuncProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func GetMFATokenFunc(configs Configs) (func() (string, error), bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(MFATokenFuncProvider); ok {
			v, err := p.GetMFATokenFunc()
			if err != nil {
				return nil, false, err
			}
			if v != nil {
				return v, true, nil
			}
		}
	}

	return nil, false, nil
}

// WithEC2MetadataRegion provides a RegionProvider that retrieves the region
// from the EC2 Metadata service.
//
// TODO add this provider to the default config loading?
type WithEC2MetadataRegion struct {
	ctx    context.Context
	client *ec2metadata.Client
}

// NewWithEC2MetadataRegion function takes in a context and an ec2metadataClient,
// returns a WithEC2MetadataRegion region provider
//
// Usage:
// ec2metaClient := ec2metadata.New(defaults.Config())
//
// cfg, err := external.LoadDefaultAWSConfig(
//    external.NewWithEC2MetadataRegion(ctx, ec2metaClient),
// )
//
func NewWithEC2MetadataRegion(ctx context.Context, client *ec2metadata.Client) WithEC2MetadataRegion {
	return WithEC2MetadataRegion{
		ctx:    ctx,
		client: client,
	}
}

// GetRegion attempts to retrieve the region from EC2 Metadata service.
func (p WithEC2MetadataRegion) GetRegion() (string, error) {
	return p.client.Region(p.ctx)
}

// EnableEndpointDiscoveryProvider provides access to the
type EnableEndpointDiscoveryProvider interface {
	GetEnableEndpointDiscovery() (value, found bool, err error)
}

// WithEnableEndpointDiscovery provides a wrapping type of a bool to satisfy
// the EnableEndpointDiscoveryProvider interface.
type WithEnableEndpointDiscovery bool

// GetEnableEndpointDiscovery returns whether to enable service endpoint discovery
func (w WithEnableEndpointDiscovery) GetEnableEndpointDiscovery() (value, found bool, err error) {
	return bool(w), true, nil
}

// GetEnableEndpointDiscovery searches the provided configs and returns the value for
// EndpointDiscoveryEnabled.
func GetEnableEndpointDiscovery(configs Configs) (value, found bool, err error) {
	for _, cfg := range configs {
		if p, ok := cfg.(EnableEndpointDiscoveryProvider); ok {
			value, found, err = p.GetEnableEndpointDiscovery()
			if err != nil {
				return false, false, err
			}
			if found {
				break
			}
		}
	}

	return value, found, err
}

// WithAssumeRoleDuration provides a wrapping type of a time.Duration to satisfy
type WithAssumeRoleDuration time.Duration

// GetAssumeRoleDuration returns the wrapped time.Duration value to use when setting
// the assume role credentials duration.
func (w WithAssumeRoleDuration) GetAssumeRoleDuration() (time.Duration, bool, error) {
	return time.Duration(w), true, nil
}

// HandlersFunc is a function pointer that takes a list of handlers and returns the modified set of handlers to use
type HandlersFunc func(aws.Handlers) aws.Handlers

// HandlersFuncProvider provides access to the configuration handlers
type HandlersFuncProvider interface {
	GetHandlersFunc() (HandlersFunc, bool, error)
}

// WithHandlersFunc implements the HandlersFuncProvider and delegates to the wrapped function
type WithHandlersFunc HandlersFunc

// GetHandlersFunc returns the wrapped haundlers function
func (w WithHandlersFunc) GetHandlersFunc() (HandlersFunc, bool, error) {
	return HandlersFunc(w), true, nil
}

// GetHandlersFunc searches the provided configs and returns the first HandlersFunc returned
// by a configuration provider.
func GetHandlersFunc(configs Configs) (f HandlersFunc, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(HandlersFuncProvider); ok {
			f, found, err = p.GetHandlersFunc()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return f, found, err
}

// EndpointResolverFunc is a function that is given the default EndpointResolver and returns an aws.EndpointResolver
// that will be used
type EndpointResolverFunc func(aws.EndpointResolver) aws.EndpointResolver

// EndpointResolverFuncProvider is an interface for retrieving an aws.EndpointResolver from a configuration source
type EndpointResolverFuncProvider interface {
	GetEndpointResolverFunc() (EndpointResolverFunc, bool, error)
}

// WithEndpointResolverFunc wraps a aws.EndpointResolver value to satisfy the EndpointResolverFuncProvider interface
type WithEndpointResolverFunc EndpointResolverFunc

// GetEndpointResolverFunc returns the wrapped EndpointResolverFunc
func (w WithEndpointResolverFunc) GetEndpointResolverFunc() (EndpointResolverFunc, bool, error) {
	return EndpointResolverFunc(w), true, nil
}

// GetEndpointResolverFunc searches the provided config sources for a EndpointResolverFunc that can be used
// to configure the aws.Config.EndpointResolver value.
func GetEndpointResolverFunc(configs Configs) (f EndpointResolverFunc, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(EndpointResolverFuncProvider); ok {
			f, found, err = p.GetEndpointResolverFunc()
			if err != nil {
				return nil, false, err
			}
		}
	}

	return f, found, err
}

// EC2RoleCredentialProviderOptions is an interface for retrieving a function for setting
// the ec2rolecreds.Provider options.
type EC2RoleCredentialProviderOptions interface {
	GetEC2RoleCredentialProviderOptions() (func(*ec2rolecreds.ProviderOptions), bool, error)
}

// WithEC2RoleCredentialProviderOptions wraps a function and satisfies the EC2RoleCredentialProviderOptions interface
type WithEC2RoleCredentialProviderOptions func(*ec2rolecreds.ProviderOptions)

// GetEC2RoleCredentialProviderOptions returns the wrapped function
func (w WithEC2RoleCredentialProviderOptions) GetEC2RoleCredentialProviderOptions() (func(*ec2rolecreds.ProviderOptions), bool, error) {
	return w, true, nil
}

// GetEC2RoleCredentialProviderOptions searches the slice of configs and returns the first function found
func GetEC2RoleCredentialProviderOptions(configs Configs) (f func(*ec2rolecreds.ProviderOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(EC2RoleCredentialProviderOptions); ok {
			f, found, err = p.GetEC2RoleCredentialProviderOptions()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return f, found, err
}

// EndpointCredentialProviderOptions is an interface for retrieving a function for setting
// the endpointcreds.ProviderOptions.
type EndpointCredentialProviderOptions interface {
	GetEndpointCredentialProviderOptions() (func(*endpointcreds.ProviderOptions), bool, error)
}

// WithEndpointCredentialProviderOptions wraps a function and satisfies the EC2RoleCredentialProviderOptions interface
type WithEndpointCredentialProviderOptions func(*endpointcreds.ProviderOptions)

// GetEndpointCredentialProviderOptions returns the wrapped function
func (w WithEndpointCredentialProviderOptions) GetEndpointCredentialProviderOptions() (func(*endpointcreds.ProviderOptions), bool, error) {
	return w, true, nil
}

// GetEndpointCredentialProviderOptions searches the slice of configs and returns the first function found
func GetEndpointCredentialProviderOptions(configs Configs) (f func(*endpointcreds.ProviderOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(EndpointCredentialProviderOptions); ok {
			f, found, err = p.GetEndpointCredentialProviderOptions()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return f, found, err
}

// ProcessCredentialProviderOptions is an interface for retrieving a function for setting
// the processcreds.ProviderOptions.
type ProcessCredentialProviderOptions interface {
	GetProcessCredentialProviderOptions() (func(*processcreds.ProviderOptions), bool, error)
}

// WithProcessCredentialProviderOptions wraps a function and satisfies the EC2RoleCredentialProviderOptions interface
type WithProcessCredentialProviderOptions func(*processcreds.ProviderOptions)

// GetProcessCredentialProviderOptions returns the wrapped function
func (w WithProcessCredentialProviderOptions) GetProcessCredentialProviderOptions() (func(*processcreds.ProviderOptions), bool, error) {
	return w, true, nil
}

// GetProcessCredentialProviderOptions searches the slice of configs and returns the first function found
func GetProcessCredentialProviderOptions(configs Configs) (f func(*processcreds.ProviderOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(ProcessCredentialProviderOptions); ok {
			f, found, err = p.GetProcessCredentialProviderOptions()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return f, found, err
}

// AssumeRoleCredentialProviderOptions is an interface for retrieving a function for setting
// the stscreds.AssumeRoleProviderOptions.
type AssumeRoleCredentialProviderOptions interface {
	GetAssumeRoleCredentialProviderOptions() (func(*stscreds.AssumeRoleProviderOptions), bool, error)
}

// WithAssumeRoleCredentialProviderOptions wraps a function and satisfies the EC2RoleCredentialProviderOptions interface
type WithAssumeRoleCredentialProviderOptions func(*stscreds.AssumeRoleProviderOptions)

// GetAssumeRoleCredentialProviderOptions returns the wrapped function
func (w WithAssumeRoleCredentialProviderOptions) GetAssumeRoleCredentialProviderOptions() (func(*stscreds.AssumeRoleProviderOptions), bool, error) {
	return w, true, nil
}

// GetAssumeRoleCredentialProviderOptions searches the slice of configs and returns the first function found
func GetAssumeRoleCredentialProviderOptions(configs Configs) (f func(*stscreds.AssumeRoleProviderOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(AssumeRoleCredentialProviderOptions); ok {
			f, found, err = p.GetAssumeRoleCredentialProviderOptions()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return f, found, err
}

// WebIdentityCredentialProviderOptions is an interface for retrieving a function for setting
// the stscreds.WebIdentityCredentialProviderOptions.
type WebIdentityCredentialProviderOptions interface {
	GetWebIdentityCredentialProviderOptions() (func(*stscreds.WebIdentityRoleProviderOptions), bool, error)
}

// WithWebIdentityCredentialProviderOptions wraps a function and satisfies the EC2RoleCredentialProviderOptions interface
type WithWebIdentityCredentialProviderOptions func(*stscreds.WebIdentityRoleProviderOptions)

// GetWebIdentityCredentialProviderOptions returns the wrapped function
func (w WithWebIdentityCredentialProviderOptions) GetWebIdentityCredentialProviderOptions() (func(*stscreds.WebIdentityRoleProviderOptions), bool, error) {
	return w, true, nil
}

// GetWebIdentityCredentialProviderOptions searches the slice of configs and returns the first function found
func GetWebIdentityCredentialProviderOptions(configs Configs) (f func(*stscreds.WebIdentityRoleProviderOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(WebIdentityCredentialProviderOptions); ok {
			f, found, err = p.GetWebIdentityCredentialProviderOptions()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return f, found, err
}

// DefaultRegionProvider is an interface for retrieving a default region if a region was not resolved from other sources
type DefaultRegionProvider interface {
	GetDefaultRegion() (string, bool, error)
}

// WithDefaultRegion wraps a string and satisfies the DefaultRegionProvider interface
type WithDefaultRegion string

// GetDefaultRegion returns wrapped fallback region
func (w WithDefaultRegion) GetDefaultRegion() (string, bool, error) {
	return string(w), true, nil
}

// GetDefaultRegion searches the slice of configs and returns the first fallback region found
func GetDefaultRegion(configs Configs) (value string, found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(DefaultRegionProvider); ok {
			value, found, err = p.GetDefaultRegion()
			if err != nil {
				return "", false, err
			}
			if found {
				break
			}
		}
	}

	return value, found, err
}

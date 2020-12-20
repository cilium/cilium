package config

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/ec2imds"
	"github.com/awslabs/smithy-go/logging"
	"github.com/awslabs/smithy-go/middleware"
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

// getSharedConfigProfile searches the configs for a SharedConfigProfileProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getSharedConfigProfile(configs configs) (string, bool, error) {
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
// are used when loading the SharedConfig.
type WithSharedConfigFiles []string

// GetSharedConfigFiles returns the slice of shared config files.
func (c WithSharedConfigFiles) GetSharedConfigFiles() ([]string, error) {
	return c, nil
}

// getSharedConfigFiles searchds the configs for a SharedConfigFilesProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getSharedConfigFiles(configs configs) ([]string, bool, error) {
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
	return v, nil
}

// getCustomCABundle searchds the configs for a CustomCABundleProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getCustomCABundle(configs configs) ([]byte, bool, error) {
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

// getRegion searchds the configs for a RegionProvider and returns the value
// if found. Returns an error if a provider fails before a value is found.
func getRegion(configs configs) (string, bool, error) {
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

// WithEC2IMDSRegion provides a RegionProvider that retrieves the region
// from the EC2 Metadata service.
//
// TODO should this provider be added to the default config loading?
type WithEC2IMDSRegion struct {
	// If unset will be defaulted to Background context
	Context context.Context

	// If unset will default to generic EC2 IMDS client.
	Client *ec2imds.Client
}

// GetRegion attempts to retrieve the region from EC2 Metadata service.
func (p WithEC2IMDSRegion) GetRegion() (string, error) {
	ctx := p.Context
	if ctx == nil {
		ctx = context.Background()
	}

	client := p.Client
	if client == nil {
		client = ec2imds.New(ec2imds.Options{})
	}

	result, err := p.Client.GetRegion(ctx, nil)
	if err != nil {
		return "", err
	}

	return result.Region, nil
}

// CredentialsProviderProvider provides access to the credentials external
// configuration value.
type CredentialsProviderProvider interface {
	GetCredentialsProvider() (aws.CredentialsProvider, bool, error)
}

// WithCredentialsProvider provides wrapping of a credentials Value to satisfy the
// CredentialsProviderProvider interface.
func WithCredentialsProvider(provider aws.CredentialsProvider) CredentialsProviderProvider {
	return withCredentialsProvider{CredentialsProvider: provider}
}

type withCredentialsProvider struct {
	aws.CredentialsProvider
}

// GetCredentialsProvider returns the credentials value.
func (v withCredentialsProvider) GetCredentialsProvider() (aws.CredentialsProvider, bool, error) {
	if v.CredentialsProvider == nil {
		return nil, false, nil
	}

	return v.CredentialsProvider, true, nil
}

// getCredentialsProvider searches the configs for a CredentialsProviderProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func getCredentialsProvider(configs configs) (p aws.CredentialsProvider, found bool, err error) {
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

// ProcessCredentialOptions is an interface for retrieving a function for setting
// the processcreds.Options.
type ProcessCredentialOptions interface {
	GetProcessCredentialOptions() (func(*processcreds.Options), bool, error)
}

// WithProcessCredentialOptions wraps a function and satisfies the
// ProcessCredentialOptions interface
type WithProcessCredentialOptions func(*processcreds.Options)

// GetProcessCredentialOptions returns the wrapped function
func (w WithProcessCredentialOptions) GetProcessCredentialOptions() (func(*processcreds.Options), bool, error) {
	return w, true, nil
}

// getProcessCredentialOptions searches the slice of configs and returns the first function found
func getProcessCredentialOptions(configs configs) (f func(*processcreds.Options), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(ProcessCredentialOptions); ok {
			f, found, err = p.GetProcessCredentialOptions()
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

// EC2RoleCredentialOptionsProvider is an interface for retrieving a function
// for setting the ec2rolecreds.Provider options.
type EC2RoleCredentialOptionsProvider interface {
	GetEC2RoleCredentialOptions() (func(*ec2rolecreds.Options), bool, error)
}

// WithEC2RoleCredentialOptions wraps a function and satisfies the
// EC2RoleCredentialOptionsProvider interface
type WithEC2RoleCredentialOptions func(*ec2rolecreds.Options)

// GetEC2RoleCredentialOptions returns the wrapped function
func (w WithEC2RoleCredentialOptions) GetEC2RoleCredentialOptions() (func(*ec2rolecreds.Options), bool, error) {
	return w, true, nil
}

// getEC2RoleCredentialProviderOptions searches the slice of configs and returns the first function found
func getEC2RoleCredentialProviderOptions(configs configs) (f func(*ec2rolecreds.Options), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(EC2RoleCredentialOptionsProvider); ok {
			f, found, err = p.GetEC2RoleCredentialOptions()
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

// getDefaultRegion searches the slice of configs and returns the first fallback region found
func getDefaultRegion(configs configs) (value string, found bool, err error) {
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

// EndpointCredentialOptionsProvider is an interface for retrieving a function for setting
// the endpointcreds.ProviderOptions.
type EndpointCredentialOptionsProvider interface {
	GetEndpointCredentialOptions() (func(*endpointcreds.Options), bool, error)
}

// WithEndpointCredentialOptions wraps a function and satisfies the EC2RoleCredentialOptionsProvider interface
type WithEndpointCredentialOptions func(*endpointcreds.Options)

// GetEndpointCredentialOptions returns the wrapped function
func (w WithEndpointCredentialOptions) GetEndpointCredentialOptions() (func(*endpointcreds.Options), bool, error) {
	return w, true, nil
}

// getEndpointCredentialProviderOptions searches the slice of configs and returns the first function found
func getEndpointCredentialProviderOptions(configs configs) (f func(*endpointcreds.Options), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(EndpointCredentialOptionsProvider); ok {
			f, found, err = p.GetEndpointCredentialOptions()
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

// WebIdentityRoleCredentialOptionsProvider is an interface for retrieving a function for setting
// the stscreds.WebIdentityRoleProvider.
type WebIdentityRoleCredentialOptionsProvider interface {
	GetWebIdentityRoleCredentialOptions() (func(*stscreds.WebIdentityRoleOptions), bool, error)
}

// WithWebIdentityRoleCredentialOptions wraps a function and satisfies the EC2RoleCredentialOptionsProvider interface
type WithWebIdentityRoleCredentialOptions func(*stscreds.WebIdentityRoleOptions)

// GetWebIdentityRoleCredentialOptions returns the wrapped function
func (w WithWebIdentityRoleCredentialOptions) GetWebIdentityRoleCredentialOptions() (func(*stscreds.WebIdentityRoleOptions), bool, error) {
	return w, true, nil
}

// getWebIdentityCredentialProviderOptions searches the slice of configs and returns the first function found
func getWebIdentityCredentialProviderOptions(configs configs) (f func(*stscreds.WebIdentityRoleOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(WebIdentityRoleCredentialOptionsProvider); ok {
			f, found, err = p.GetWebIdentityRoleCredentialOptions()
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

// AssumeRoleCredentialOptionsProvider is an interface for retrieving a function for setting
// the stscreds.AssumeRoleOptions.
type AssumeRoleCredentialOptionsProvider interface {
	GetAssumeRoleCredentialOptions() (func(*stscreds.AssumeRoleOptions), bool, error)
}

// WithAssumeRoleCredentialOptions wraps a function and satisfies the EC2RoleCredentialOptionsProvider interface
type WithAssumeRoleCredentialOptions func(*stscreds.AssumeRoleOptions)

// GetAssumeRoleCredentialOptions returns the wrapped function
func (w WithAssumeRoleCredentialOptions) GetAssumeRoleCredentialOptions() (func(*stscreds.AssumeRoleOptions), bool, error) {
	return w, true, nil
}

// getAssumeRoleCredentialProviderOptions searches the slice of configs and returns the first function found
func getAssumeRoleCredentialProviderOptions(configs configs) (f func(*stscreds.AssumeRoleOptions), found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(AssumeRoleCredentialOptionsProvider); ok {
			f, found, err = p.GetAssumeRoleCredentialOptions()
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

// HTTPClient is an HTTP client implementation
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// HTTPClientProvider is an interface for retrieving an HTTPClient.
type HTTPClientProvider interface {
	GetHTTPClient() (HTTPClient, bool, error)
}

// withHTTPClient wraps a HTTPClient and satisfies the HTTPClientProvider interface
type withHTTPClient struct {
	HTTPClient
}

// WithHTTPClient wraps a HTTPClient and satisfies the HTTPClientProvider interface
func WithHTTPClient(client HTTPClient) HTTPClientProvider {
	return withHTTPClient{HTTPClient: client}
}

// GetHTTPClient returns the wrapped HTTPClient. Returns an error if the wrapped client is nil.
func (w withHTTPClient) GetHTTPClient() (HTTPClient, bool, error) {
	if w.HTTPClient == nil {
		return nil, false, fmt.Errorf("http client must not be nil")
	}
	return w.HTTPClient, true, nil
}

// getHTTPClient searches the slice of configs and returns the first HTTPClient found.
func getHTTPClient(configs configs) (c HTTPClient, found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(HTTPClientProvider); ok {
			c, found, err = p.GetHTTPClient()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return c, found, err
}

// APIOptionsProvider is an interface for retrieving APIOptions.
type APIOptionsProvider interface {
	GetAPIOptions() ([]func(*middleware.Stack) error, bool, error)
}

// WithAPIOptions wraps a slice of middlewares stack mutators and satisfies the APIOptionsProvider interface.
type WithAPIOptions []func(*middleware.Stack) error

// GetAPIOptions returns the wrapped middleware stack mutators.
func (w WithAPIOptions) GetAPIOptions() ([]func(*middleware.Stack) error, bool, error) {
	return w, true, nil
}

// getAPIOptions searches the slice of configs and returns the first APIOptions found.
func getAPIOptions(configs configs) (o []func(*middleware.Stack) error, found bool, err error) {
	for _, config := range configs {
		if p, ok := config.(APIOptionsProvider); ok {
			o, found, err = p.GetAPIOptions()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return o, found, err
}

// EndpointResolverProvider is an interface for retrieving an aws.EndpointResolver from a configuration source
type EndpointResolverProvider interface {
	GetEndpointResolver() (aws.EndpointResolver, bool, error)
}

type withEndpointResolver struct {
	aws.EndpointResolver
}

// WithEndpointResolver wraps a aws.EndpointResolver value to satisfy the EndpointResolverProvider interface
func WithEndpointResolver(resolver aws.EndpointResolver) EndpointResolverProvider {
	return withEndpointResolver{EndpointResolver: resolver}
}

// GetEndpointResolver returns the wrapped EndpointResolver
func (w withEndpointResolver) GetEndpointResolver() (aws.EndpointResolver, bool, error) {
	return w.EndpointResolver, true, nil
}

// getEndpointResolver searches the provided config sources for a EndpointResolverFunc that can be used
// to configure the aws.Config.EndpointResolver value.
func getEndpointResolver(configs configs) (f aws.EndpointResolver, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(EndpointResolverProvider); ok {
			f, found, err = p.GetEndpointResolver()
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

// LoggerProvider is an interface for retrieving a logging.Logger from a configuration source.
type LoggerProvider interface {
	GetLogger() (logging.Logger, bool, error)
}

type withLogger struct {
	logging.Logger
}

// WithLogger wraps a logging.Logger value to satisfy the LoggerProvider interface.
func WithLogger(logger logging.Logger) LoggerProvider {
	return withLogger{Logger: logger}
}

func (w withLogger) GetLogger() (logging.Logger, bool, error) {
	return w.Logger, true, nil
}

// getLogger searches the provided config sources for a logging.Logger that can be used
// to configure the aws.Config.Logger value.
func getLogger(configs configs) (l logging.Logger, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(LoggerProvider); ok {
			l, found, err = p.GetLogger()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return l, found, err
}

// ClientLogModeProvider is an interface for retrieving the aws.ClientLogMode from a configuration source.
type ClientLogModeProvider interface {
	GetClientLogMode() (aws.ClientLogMode, bool, error)
}

// WithClientLogMode is a ClientLogModeProvider implementation that wraps a aws.ClientLogMode value.
type WithClientLogMode aws.ClientLogMode

// GetClientLogMode returns the wrapped aws.ClientLogMode
func (w WithClientLogMode) GetClientLogMode() (aws.ClientLogMode, bool, error) {
	return aws.ClientLogMode(w), true, nil
}

func getClientLogMode(configs configs) (m aws.ClientLogMode, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(ClientLogModeProvider); ok {
			m, found, err = p.GetClientLogMode()
			if err != nil {
				return 0, false, err
			}
			if found {
				break
			}
		}
	}
	return m, found, err
}

// LogConfigurationWarningsProvider is an interface for retrieving a boolean indicating whether configuration issues should
// be logged when encountered when loading from config sources.
type LogConfigurationWarningsProvider interface {
	GetLogConfigurationWarnings() (bool, bool, error)
}

// WithLogConfigurationWarnings implements a LogConfigurationWarningsProvider and returns the wrapped boolean value.
type WithLogConfigurationWarnings bool

// GetLogConfigurationWarnings returns the wrapped boolean.
func (w WithLogConfigurationWarnings) GetLogConfigurationWarnings() (bool, bool, error) {
	return bool(w), true, nil
}

func getLogConfigurationWarnings(configs configs) (v bool, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(LogConfigurationWarningsProvider); ok {
			v, found, err = p.GetLogConfigurationWarnings()
			if err != nil {
				return false, false, err
			}
			if found {
				break
			}
		}
	}
	return v, found, err
}

// RetryProvider is an configuration provider for custom Retryer.
type RetryProvider interface {
	GetRetryer() (aws.Retryer, bool, error)
}

// WithRetryer returns a RetryProvider for the SDK retryer provided.
func WithRetryer(retryer aws.Retryer) RetryProvider {
	return retryProvider{retryer: retryer}
}

type retryProvider struct {
	retryer aws.Retryer
}

func (p retryProvider) GetRetryer() (aws.Retryer, bool, error) {
	return p.retryer, true, nil
}

func getRetryer(configs configs) (v aws.Retryer, found bool, err error) {
	for _, c := range configs {
		if p, ok := c.(RetryProvider); ok {
			v, found, err = p.GetRetryer()
			if err != nil {
				return nil, false, err
			}
			if found {
				break
			}
		}
	}
	return v, found, err
}

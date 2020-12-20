package config

import (
	"fmt"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/ec2imds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	// valid credential source values
	credSourceEc2Metadata  = "Ec2InstanceMetadata"
	credSourceEnvironment  = "Environment"
	credSourceECSContainer = "EcsContainer"
)

var (
	ecsContainerEndpoint = "http://169.254.170.2" // not constant to allow for swapping during unit-testing

)

// resolveCredentials extracts a credential provider from slice of config sources.
//
// If an explict credential provider is not found the resolver will fallback to resolving
// credentials by extracting a credential provider from EnvConfig and SharedConfig.
func resolveCredentials(cfg *aws.Config, configs configs) error {
	found, err := resolveCredentialProvider(cfg, configs)
	if err != nil {
		return err
	}
	if found {
		return nil
	}

	err = resolveCredentialChain(cfg, configs)
	if err != nil {
		return err
	}

	return nil
}

// resolveCredentialProvider extracts the first instance of Credentials from the
// config slices.
//
// The resolved CredentialProvider will be wrapped in a cache to ensure the
// credentials are only refreshed when needed. This also protects the
// credential provider to be used concurrently.
//
// Config providers used:
// * CredentialsProviderProvider
func resolveCredentialProvider(cfg *aws.Config, cfgs configs) (bool, error) {
	credProvider, found, err := getCredentialsProvider(cfgs)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}

	cfg.Credentials = &aws.CredentialsCache{Provider: credProvider}

	return true, nil
}

// resolveCredentialChain resolves a credential provider chain using EnvConfig
// and SharedConfig if present in the slice of provided configs.
//
// The resolved CredentialProvider will be wrapped in a cache to ensure the
// credentials are only refreshed when needed. This also protects the
// credential provider to be used concurrently.
func resolveCredentialChain(cfg *aws.Config, configs configs) (err error) {
	_, sharedProfileSet, err := getSharedConfigProfile(configs)
	if err != nil {
		return err
	}

	envConfig, sharedConfig, other := getAWSConfigSources(configs)

	switch {
	case sharedProfileSet:
		err = resolveCredsFromProfile(cfg, envConfig, sharedConfig, other)
	case envConfig.Credentials.HasKeys():
		cfg.Credentials = credentials.StaticCredentialsProvider{Value: envConfig.Credentials}
	case len(envConfig.WebIdentityTokenFilePath) > 0:
		err = assumeWebIdentity(cfg, envConfig.WebIdentityTokenFilePath, envConfig.RoleARN, envConfig.RoleSessionName, configs)
	default:
		err = resolveCredsFromProfile(cfg, envConfig, sharedConfig, other)
	}
	if err != nil {
		return err
	}

	// Wrap the resolved provider in a cache so the SDK will cache credentials.
	cfg.Credentials = &aws.CredentialsCache{Provider: cfg.Credentials}

	return nil
}

func resolveCredsFromProfile(cfg *aws.Config, envConfig *EnvConfig, sharedConfig *SharedConfig, configs configs) (err error) {

	switch {
	case sharedConfig.Source != nil:
		// Assume IAM role with credentials source from a different profile.
		err = resolveCredsFromProfile(cfg, envConfig, sharedConfig.Source, configs)

	case sharedConfig.Credentials.HasKeys():
		// Static Credentials from Shared Config/Credentials file.
		cfg.Credentials = credentials.StaticCredentialsProvider{
			Value: sharedConfig.Credentials,
		}

	case len(sharedConfig.CredentialProcess) != 0:
		// Get credentials from CredentialProcess
		err = processCredentials(cfg, sharedConfig, configs)

	case len(sharedConfig.CredentialSource) != 0:
		err = resolveCredsFromSource(cfg, envConfig, sharedConfig, configs)

	case len(sharedConfig.WebIdentityTokenFile) != 0:
		// Credentials from Assume Web Identity token require an IAM Role, and
		// that roll will be assumed. May be wrapped with another assume role
		// via SourceProfile.
		err = assumeWebIdentity(cfg, sharedConfig.WebIdentityTokenFile, sharedConfig.RoleARN, sharedConfig.RoleSessionName, configs)

	case len(envConfig.ContainerCredentialsEndpoint) != 0:
		err = resolveLocalHTTPCredProvider(cfg, envConfig.ContainerCredentialsEndpoint, envConfig.ContainerAuthorizationToken, configs)

	case len(envConfig.ContainerCredentialsRelativePath) != 0:
		err = resolveHTTPCredProvider(cfg, ecsContainerURI(envConfig.ContainerCredentialsRelativePath), envConfig.ContainerAuthorizationToken, configs)

	default:
		err = resolveEC2RoleCredentials(cfg, configs)
	}
	if err != nil {
		return err
	}

	if len(sharedConfig.RoleARN) > 0 {
		return credsFromAssumeRole(cfg, sharedConfig, configs)
	}

	return nil
}

func ecsContainerURI(path string) string {
	return fmt.Sprintf("%s%s", ecsContainerEndpoint, path)
}

func processCredentials(cfg *aws.Config, sharedConfig *SharedConfig, configs configs) error {
	var opts []func(*processcreds.Options)

	options, found, err := getProcessCredentialOptions(configs)
	if err != nil {
		return err
	}
	if found {
		opts = append(opts, options)
	}

	cfg.Credentials = processcreds.NewProvider(sharedConfig.CredentialProcess, opts...)

	return nil
}

func resolveLocalHTTPCredProvider(cfg *aws.Config, endpointURL, authToken string, configs configs) error {
	var resolveErr error

	parsed, err := url.Parse(endpointURL)
	if err != nil {
		resolveErr = fmt.Errorf("invalid URL, %w", err)
	} else {
		host := parsed.Hostname()
		if len(host) == 0 {
			resolveErr = fmt.Errorf("unable to parse host from local HTTP cred provider URL")
		} else if isLoopback, loopbackErr := isLoopbackHost(host); loopbackErr != nil {
			resolveErr = fmt.Errorf("failed to resolve host %q, %v", host, loopbackErr)
		} else if !isLoopback {
			resolveErr = fmt.Errorf("invalid endpoint host, %q, only loopback hosts are allowed", host)
		}
	}

	if resolveErr != nil {
		return resolveErr
	}

	return resolveHTTPCredProvider(cfg, endpointURL, authToken, configs)
}

func resolveHTTPCredProvider(cfg *aws.Config, url, authToken string, configs configs) error {
	optFns := []func(*endpointcreds.Options){
		func(options *endpointcreds.Options) {
			options.ExpiryWindow = 5 * time.Minute
			if len(authToken) != 0 {
				options.AuthorizationToken = authToken
			}
			options.APIOptions = cfg.APIOptions
			options.Retryer = cfg.Retryer
		},
	}

	optFn, found, err := getEndpointCredentialProviderOptions(configs)
	if err != nil {
		return err
	}
	if found {
		optFns = append(optFns, optFn)
	}

	provider := endpointcreds.New(url, optFns...)

	cfg.Credentials = provider

	return nil
}

func resolveCredsFromSource(cfg *aws.Config, envConfig *EnvConfig, sharedCfg *SharedConfig, configs configs) (err error) {
	switch sharedCfg.CredentialSource {
	case credSourceEc2Metadata:
		return resolveEC2RoleCredentials(cfg, configs)

	case credSourceEnvironment:
		cfg.Credentials = credentials.StaticCredentialsProvider{Value: envConfig.Credentials}

	case credSourceECSContainer:
		if len(envConfig.ContainerCredentialsRelativePath) == 0 {
			return fmt.Errorf("EcsContainer was specified as the credential_source, but 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' was not set")
		}
		return resolveHTTPCredProvider(cfg, ecsContainerURI(envConfig.ContainerCredentialsRelativePath), envConfig.ContainerAuthorizationToken, configs)

	default:
		return fmt.Errorf("credential_source values must be EcsContainer, Ec2InstanceMetadata, or Environment")
	}

	return nil
}

func resolveEC2RoleCredentials(cfg *aws.Config, configs configs) error {
	optFns := make([]func(*ec2rolecreds.Options), 0, 2)

	optFn, found, err := getEC2RoleCredentialProviderOptions(configs)
	if err != nil {
		return err
	}
	if found {
		optFns = append(optFns, optFn)
	}

	optFns = append(optFns, func(o *ec2rolecreds.Options) {
		// Only define a client from config if not already defined.
		if o.Client != nil {
			o.Client = ec2imds.New(ec2imds.Options{
				HTTPClient: cfg.HTTPClient,
				Retryer:    cfg.Retryer,
			})
		}
	})

	provider := ec2rolecreds.New(ec2rolecreds.Options{
		ExpiryWindow: 5 * time.Minute,
	}, optFns...)

	cfg.Credentials = provider

	return nil
}

func getAWSConfigSources(cfgs configs) (*EnvConfig, *SharedConfig, configs) {
	var (
		envConfig    *EnvConfig
		sharedConfig *SharedConfig
		other        configs
	)

	for i := range cfgs {
		switch c := cfgs[i].(type) {
		case EnvConfig:
			if envConfig == nil {
				envConfig = &c
			}
		case *EnvConfig:
			if envConfig == nil {
				envConfig = c
			}
		case SharedConfig:
			if sharedConfig == nil {
				sharedConfig = &c
			}
		case *SharedConfig:
			if envConfig == nil {
				sharedConfig = c
			}
		default:
			other = append(other, c)
		}
	}

	if envConfig == nil {
		envConfig = &EnvConfig{}
	}

	if sharedConfig == nil {
		sharedConfig = &SharedConfig{}
	}

	return envConfig, sharedConfig, other
}

// AssumeRoleTokenProviderNotSetError is an error returned when creating a
// session when the MFAToken option is not set when shared config is configured
// load assume a role with an MFA token.
type AssumeRoleTokenProviderNotSetError struct{}

// Error is the error message
func (e AssumeRoleTokenProviderNotSetError) Error() string {
	return fmt.Sprintf("assume role with MFA enabled, but AssumeRoleTokenProvider session option not set.")
}

func assumeWebIdentity(cfg *aws.Config, filepath string, roleARN, sessionName string, configs configs) error {
	if len(filepath) == 0 {
		return fmt.Errorf("token file path is not set")
	}

	if len(roleARN) == 0 {
		return fmt.Errorf("role ARN is not set")
	}

	optFns := []func(*stscreds.WebIdentityRoleOptions){
		func(options *stscreds.WebIdentityRoleOptions) {
			options.RoleSessionName = sessionName
		},
	}

	optFn, found, err := getWebIdentityCredentialProviderOptions(configs)
	if err != nil {
		return err
	}
	if found {
		optFns = append(optFns, optFn)
	}

	provider := stscreds.NewWebIdentityRoleProvider(sts.NewFromConfig(cfg.Copy()), roleARN, stscreds.IdentityTokenFile(filepath), optFns...)

	cfg.Credentials = provider

	return nil
}

func credsFromAssumeRole(cfg *aws.Config, sharedCfg *SharedConfig, configs configs) (err error) {
	optFns := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = sharedCfg.RoleSessionName
			if sharedCfg.RoleDurationSeconds != nil {
				if *sharedCfg.RoleDurationSeconds/time.Minute > 15 {
					options.Duration = *sharedCfg.RoleDurationSeconds
				}
			}
			// Assume role with external ID
			if len(sharedCfg.ExternalID) > 0 {
				options.ExternalID = aws.String(sharedCfg.ExternalID)
			}

			// Assume role with MFA
			if len(sharedCfg.MFASerial) != 0 {
				options.SerialNumber = aws.String(sharedCfg.MFASerial)
			}
		},
	}

	optFn, found, err := getAssumeRoleCredentialProviderOptions(configs)
	if err != nil {
		return err
	}
	if found {
		optFns = append(optFns, optFn)
	}

	{
		// Synthesize options early to validate configuration errors sooner to ensure a token provider
		// is present if the SerialNumber was set.
		var o stscreds.AssumeRoleOptions
		for _, fn := range optFns {
			fn(&o)
		}
		if o.TokenProvider == nil && o.SerialNumber != nil {
			return AssumeRoleTokenProviderNotSetError{}
		}
	}

	cfg.Credentials = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg.Copy()), sharedCfg.RoleARN, optFns...)

	return nil
}

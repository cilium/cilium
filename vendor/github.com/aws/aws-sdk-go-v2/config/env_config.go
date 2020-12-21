package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// CredentialsSourceName provides a name of the provider when config is
// loaded from environment.
const CredentialsSourceName = "EnvConfigCredentials"

// Environment variables that will be read for configuration values.
const (
	awsAccessKeyIDEnvVar = "AWS_ACCESS_KEY_ID"
	awsAccessKeyEnvVar   = "AWS_ACCESS_KEY"

	awsSecretAccessKeyEnvVar = "AWS_SECRET_ACCESS_KEY"
	awsSecretKeyEnvVar       = "AWS_SECRET_KEY"

	awsSessionTokenEnvVar = "AWS_SESSION_TOKEN"

	awsContainerCredentialsEndpointEnvVar     = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
	awsContainerCredentialsRelativePathEnvVar = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
	awsContainerPProviderAuthorizationEnvVar  = "AWS_CONTAINER_AUTHORIZATION_TOKEN"

	awsRegionEnvVar        = "AWS_REGION"
	awsDefaultRegionEnvVar = "AWS_DEFAULT_REGION"

	awsProfileEnvVar        = "AWS_PROFILE"
	awsDefaultProfileEnvVar = "AWS_DEFAULT_PROFILE"

	awsSharedCredentialsFileEnvVar = "AWS_SHARED_CREDENTIALS_FILE"

	awsConfigFileEnvVar = "AWS_CONFIG_FILE"

	awsCustomCABundleEnvVar = "AWS_CA_BUNDLE"

	awsWebIdentityTokenFilePathEnvKey = "AWS_WEB_IDENTITY_TOKEN_FILE"

	awsRoleARNEnvKey         = "AWS_ROLE_ARN"
	awsRoleSessionNameEnvKey = "AWS_ROLE_SESSION_NAME"

	awsEnableEndpointDiscoveryEnvKey = "AWS_ENABLE_ENDPOINT_DISCOVERY"

	awsS3UseARNRegionEnvVar = "AWS_S3_USE_ARN_REGION"
)

var (
	credAccessEnvKeys = []string{
		awsAccessKeyIDEnvVar,
		awsAccessKeyEnvVar,
	}
	credSecretEnvKeys = []string{
		awsSecretAccessKeyEnvVar,
		awsSecretKeyEnvVar,
	}
	regionEnvKeys = []string{
		awsRegionEnvVar,
		awsDefaultRegionEnvVar,
	}
	profileEnvKeys = []string{
		awsProfileEnvVar,
		awsDefaultProfileEnvVar,
	}
)

// EnvConfig is a collection of environment values the SDK will read
// setup config from. All environment values are optional. But some values
// such as credentials require multiple values to be complete or the values
// will be ignored.
type EnvConfig struct {
	// Environment configuration values. If set both Access Key ID and Secret Access
	// Key must be provided. Session Token and optionally also be provided, but is
	// not required.
	//
	//	# Access Key ID
	//	AWS_ACCESS_KEY_ID=AKID
	//	AWS_ACCESS_KEY=AKID # only read if AWS_ACCESS_KEY_ID is not set.
	//
	//	# Secret Access Key
	//	AWS_SECRET_ACCESS_KEY=SECRET
	//	AWS_SECRET_KEY=SECRET # only read if AWS_SECRET_ACCESS_KEY is not set.
	//
	//	# Session Token
	//	AWS_SESSION_TOKEN=TOKEN
	Credentials aws.Credentials

	// ContainerCredentialsEndpoint value is the HTTP enabled endpoint to retrieve credentials
	// using the endpointcreds.Provider
	ContainerCredentialsEndpoint string

	// ContainerCredentialsRelativePath is the relative URI path that will be used when attempting to retrieve
	// credentials from the container endpoint.
	ContainerCredentialsRelativePath string

	// ContainerAuthorizationToken is the authorization token that will be included in the HTTP Authorization
	// header when attempting to retrieve credentials from the container credentials endpoint.
	ContainerAuthorizationToken string

	// Region value will instruct the SDK where to make service API requests to. If is
	// not provided in the environment the region must be provided before a service
	// client request is made.
	//
	//	AWS_REGION=us-west-2
	//	AWS_DEFAULT_REGION=us-west-2
	Region string

	// Profile name the SDK should load use when loading shared configuration from the
	// shared configuration files. If not provided "default" will be used as the
	// profile name.
	//
	//	AWS_PROFILE=my_profile
	//	AWS_DEFAULT_PROFILE=my_profile
	SharedConfigProfile string

	// Shared credentials file path can be set to instruct the SDK to use an alternate
	// file for the shared credentials. If not set the file will be loaded from
	// $HOME/.aws/credentials on Linux/Unix based systems, and
	// %USERPROFILE%\.aws\credentials on Windows.
	//
	//	AWS_SHARED_CREDENTIALS_FILE=$HOME/my_shared_credentials
	SharedCredentialsFile string

	// Shared config file path can be set to instruct the SDK to use an alternate
	// file for the shared config. If not set the file will be loaded from
	// $HOME/.aws/config on Linux/Unix based systems, and
	// %USERPROFILE%\.aws\config on Windows.
	//
	//	AWS_CONFIG_FILE=$HOME/my_shared_config
	SharedConfigFile string

	// Sets the path to a custom Credentials Authority (CA) Bundle PEM file
	// that the SDK will use instead of the system's root CA bundle.
	// Only use this if you want to configure the SDK to use a custom set
	// of CAs.
	//
	// Enabling this option will attempt to merge the Transport
	// into the SDK's HTTP client. If the client's Transport is
	// not a http.Transport an error will be returned. If the
	// Transport's TLS config is set this option will cause the
	// SDK to overwrite the Transport's TLS config's  RootCAs value.
	//
	// Setting a custom HTTPClient in the aws.Config options will override this setting.
	// To use this option and custom HTTP client, the HTTP client needs to be provided
	// when creating the config. Not the service client.
	//
	//  AWS_CA_BUNDLE=$HOME/my_custom_ca_bundle
	CustomCABundle string

	// Enables endpoint discovery via environment variables.
	//
	//	AWS_ENABLE_ENDPOINT_DISCOVERY=true
	EnableEndpointDiscovery *bool

	// Specifies the WebIdentity token the SDK should use to assume a role
	// with.
	//
	//  AWS_WEB_IDENTITY_TOKEN_FILE=file_path
	WebIdentityTokenFilePath string

	// Specifies the IAM role arn to use when assuming an role.
	//
	//  AWS_ROLE_ARN=role_arn
	RoleARN string

	// Specifies the IAM role session name to use when assuming a role.
	//
	//  AWS_ROLE_SESSION_NAME=session_name
	RoleSessionName string

	// Specifies if the S3 service should allow ARNs to direct the region
	// the client's requests are sent to.
	//
	// AWS_S3_USE_ARN_REGION=true
	S3UseARNRegion *bool
}

// loadEnvConfig reads configuration values from the OS's environment variables.
// Returning the a Config typed EnvConfig to satisfy the ConfigLoader func type.
func loadEnvConfig(cfgs configs) (Config, error) {
	return NewEnvConfig()
}

// NewEnvConfig retrieves the SDK's environment configuration.
// See `EnvConfig` for the values that will be retrieved.
func NewEnvConfig() (EnvConfig, error) {
	var cfg EnvConfig

	creds := aws.Credentials{
		Source: CredentialsSourceName,
	}
	setStringFromEnvVal(&creds.AccessKeyID, credAccessEnvKeys)
	setStringFromEnvVal(&creds.SecretAccessKey, credSecretEnvKeys)
	if creds.HasKeys() {
		creds.SessionToken = os.Getenv(awsSessionTokenEnvVar)
		cfg.Credentials = creds
	}

	cfg.ContainerCredentialsEndpoint = os.Getenv(awsContainerCredentialsEndpointEnvVar)
	cfg.ContainerCredentialsRelativePath = os.Getenv(awsContainerCredentialsRelativePathEnvVar)
	cfg.ContainerAuthorizationToken = os.Getenv(awsContainerPProviderAuthorizationEnvVar)

	setStringFromEnvVal(&cfg.Region, regionEnvKeys)
	setStringFromEnvVal(&cfg.SharedConfigProfile, profileEnvKeys)

	cfg.SharedCredentialsFile = os.Getenv(awsSharedCredentialsFileEnvVar)
	cfg.SharedConfigFile = os.Getenv(awsConfigFileEnvVar)

	cfg.CustomCABundle = os.Getenv(awsCustomCABundleEnvVar)

	cfg.WebIdentityTokenFilePath = os.Getenv(awsWebIdentityTokenFilePathEnvKey)

	cfg.RoleARN = os.Getenv(awsRoleARNEnvKey)
	cfg.RoleSessionName = os.Getenv(awsRoleSessionNameEnvKey)

	if err := setBoolPtrFromEnvVal(&cfg.EnableEndpointDiscovery, []string{awsEnableEndpointDiscoveryEnvKey}); err != nil {
		return cfg, err
	}

	if err := setBoolPtrFromEnvVal(&cfg.S3UseARNRegion, []string{awsS3UseARNRegionEnvVar}); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// GetRegion returns the AWS Region if set in the environment. Returns an empty
// string if not set.
func (c EnvConfig) GetRegion() (string, error) {
	return c.Region, nil
}

// GetSharedConfigProfile returns the shared config profile if set in the
// environment. Returns an empty string if not set.
func (c EnvConfig) GetSharedConfigProfile() (string, error) {
	return c.SharedConfigProfile, nil
}

// GetSharedConfigFiles returns a slice of filenames set in the environment.
//
// Will return the filenames in the order of:
// * Shared Credentials
// * Shared Config
func (c EnvConfig) GetSharedConfigFiles() ([]string, error) {
	files := make([]string, 0, 2)
	if v := c.SharedCredentialsFile; len(v) > 0 {
		files = append(files, v)
	}
	if v := c.SharedConfigFile; len(v) > 0 {
		files = append(files, v)
	}

	return files, nil
}

// GetCustomCABundle returns the custom CA bundle's PEM bytes if the file was
func (c EnvConfig) GetCustomCABundle() ([]byte, error) {
	if len(c.CustomCABundle) == 0 {
		return nil, nil
	}

	return ioutil.ReadFile(c.CustomCABundle)
}

// GetEnableEndpointDiscovery returns whether to enable service endpoint discovery
func (c EnvConfig) GetEnableEndpointDiscovery() (value, ok bool, err error) {
	if c.EnableEndpointDiscovery == nil {
		return false, false, nil
	}

	return *c.EnableEndpointDiscovery, true, nil
}

// GetS3UseARNRegion returns whether to allow ARNs to direct the region
// the S3 client's requests are sent to.
func (c EnvConfig) GetS3UseARNRegion() (value, ok bool, err error) {
	if c.S3UseARNRegion == nil {
		return false, false, nil
	}

	return *c.S3UseARNRegion, true, nil
}

func setStringFromEnvVal(dst *string, keys []string) {
	for _, k := range keys {
		if v := os.Getenv(k); len(v) > 0 {
			*dst = v
			break
		}
	}
}

func setBoolPtrFromEnvVal(dst **bool, keys []string) error {
	for _, k := range keys {
		value := os.Getenv(k)
		if len(value) == 0 {
			continue
		}

		if *dst == nil {
			*dst = new(bool)
		}

		switch {
		case strings.EqualFold(value, "false"):
			**dst = false
		case strings.EqualFold(value, "true"):
			**dst = true
		default:
			return fmt.Errorf(
				"invalid value for environment variable, %s=%s, need true or false",
				k, value)
		}
		break
	}

	return nil
}

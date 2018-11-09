package external

import (
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// CredentialsSourceName provides a name of the provider when config is
// loaded from environment.
const CredentialsSourceName = "EnvConfigCredentials"

// Environment variables that will be read for configuration values.
const (
	AWSAccessKeyIDEnvVar = "AWS_ACCESS_KEY_ID"
	AWSAccessKeyEnvVar   = "AWS_ACCESS_KEY"

	AWSSecreteAccessKeyEnvVar = "AWS_SECRET_ACCESS_KEY"
	AWSSecreteKeyEnvVar       = "AWS_SECRET_KEY"

	AWSSessionTokenEnvVar = "AWS_SESSION_TOKEN"

	AWSCredentialsEndpointEnvVar = "AWS_CONTAINER_CREDENTIALS_FULL_URI"

	// TODO shorter name?
	AWSContainerCredentialsEndpointPathEnvVar = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"

	AWSRegionEnvVar        = "AWS_REGION"
	AWSDefaultRegionEnvVar = "AWS_DEFAULT_REGION"

	AWSProfileEnvVar        = "AWS_PROFILE"
	AWSDefaultProfileEnvVar = "AWS_DEFAULT_PROFILE"

	AWSSharedCredentialsFileEnvVar = "AWS_SHARED_CREDENTIALS_FILE"

	AWSConfigFileEnvVar = "AWS_CONFIG_FILE"

	AWSCustomCABundleEnvVar = "AWS_CA_BUNDLE"
)

var (
	credAccessEnvKeys = []string{
		AWSAccessKeyIDEnvVar,
		AWSAccessKeyEnvVar,
	}
	credSecretEnvKeys = []string{
		AWSSecreteAccessKeyEnvVar,
		AWSSecreteKeyEnvVar,
	}
	regionEnvKeys = []string{
		AWSRegionEnvVar,
		AWSDefaultRegionEnvVar,
	}
	profileEnvKeys = []string{
		AWSProfileEnvVar,
		AWSDefaultProfileEnvVar,
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
	//	AWS_SECRET_KEY=SECRET=SECRET # only read if AWS_SECRET_ACCESS_KEY is not set.
	//
	//	# Session Token
	//	AWS_SESSION_TOKEN=TOKEN
	Credentials aws.Credentials

	// TODO doc
	CredentialsEndpoint string

	// TODO doc, shorter name?
	ContainerCredentialsEndpointPath string

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

	// Sets the path to a custom Credentials Authroity (CA) Bundle PEM file
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
}

// LoadEnvConfig reads configuration values from the OS's environment variables.
// Returning the a Config typed EnvConfig to satisfy the ConfigLoader func type.
func LoadEnvConfig(cfgs Configs) (Config, error) {
	return NewEnvConfig()
}

// NewEnvConfig retrieves the SDK's environment configuration.
// See `EnvConfig` for the values that will be retrieved.
func NewEnvConfig() (EnvConfig, error) {
	var cfg EnvConfig

	creds := aws.Credentials{
		Source: CredentialsSourceName,
	}
	setFromEnvVal(&creds.AccessKeyID, credAccessEnvKeys)
	setFromEnvVal(&creds.SecretAccessKey, credSecretEnvKeys)
	if creds.HasKeys() {
		creds.SessionToken = os.Getenv(AWSSessionTokenEnvVar)
		cfg.Credentials = creds
	}

	cfg.CredentialsEndpoint = os.Getenv(AWSCredentialsEndpointEnvVar)
	cfg.ContainerCredentialsEndpointPath = os.Getenv(AWSContainerCredentialsEndpointPathEnvVar)

	setFromEnvVal(&cfg.Region, regionEnvKeys)
	setFromEnvVal(&cfg.SharedConfigProfile, profileEnvKeys)

	cfg.SharedCredentialsFile = os.Getenv(AWSSharedCredentialsFileEnvVar)
	cfg.SharedConfigFile = os.Getenv(AWSConfigFileEnvVar)

	cfg.CustomCABundle = os.Getenv(AWSCustomCABundleEnvVar)

	return cfg, nil
}

// GetRegion returns the AWS Region if set in the environment. Returns an empty
// string if not set.
func (c EnvConfig) GetRegion() (string, error) {
	return c.Region, nil
}

// GetCredentialsValue returns the AWS Credentials if both AccessKey and ScreteAccessKey
// are set in the environment. Returns a zero value Credentials if not set.
func (c EnvConfig) GetCredentialsValue() (aws.Credentials, error) {
	return c.Credentials, nil
}

// GetSharedConfigProfile returns the shared config profile if set in the
// environment. Returns an empty string if not set.
func (c EnvConfig) GetSharedConfigProfile() (string, error) {
	return c.SharedConfigProfile, nil
}

// GetCredentialsEndpoint returns the credentials endpoint string if set.
func (c EnvConfig) GetCredentialsEndpoint() (string, error) {
	return c.CredentialsEndpoint, nil
}

// GetContainerCredentialsEndpointPath returns the container credentails endpoint
// path string if set.
func (c EnvConfig) GetContainerCredentialsEndpointPath() (string, error) {
	return c.ContainerCredentialsEndpointPath, nil
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

func setFromEnvVal(dst *string, keys []string) {
	for _, k := range keys {
		if v := os.Getenv(k); len(v) > 0 {
			*dst = v
			break
		}
	}
}

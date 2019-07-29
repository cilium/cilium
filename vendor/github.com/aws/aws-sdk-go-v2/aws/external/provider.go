package external

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
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

// GetSharedConfigProfile searchds the Configs for a SharedConfigProfileProvider
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

// CredentialsValueProvider provides access to the credentials external
// configuration value.
type CredentialsValueProvider interface {
	GetCredentialsValue() (aws.Credentials, error)
}

// WithCredentialsValue provides wrapping of a credentials Value to satisfy the
// CredentialsValueProvider interface.
type WithCredentialsValue aws.Credentials

// GetCredentialsValue returns the credentials value.
func (v WithCredentialsValue) GetCredentialsValue() (aws.Credentials, error) {
	return aws.Credentials(v), nil
}

// GetCredentialsValue searchds the Configs for a CredentialsValueProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func GetCredentialsValue(configs Configs) (aws.Credentials, bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(CredentialsValueProvider); ok {
			v, err := p.GetCredentialsValue()
			if err != nil {
				return aws.Credentials{}, false, err
			}
			if v.HasKeys() {
				return v, true, nil
			}
		}
	}

	return aws.Credentials{}, false, nil
}

// CredentialsEndpointProvider provides access to the credentials endpoint
// external configuration value.
type CredentialsEndpointProvider interface {
	GetCredentialsEndpoint() (string, error)
}

// WithCredentialsEndpoint provides wrapping of a string to satisfy the
// CredentialsEndpointProvider interface.
type WithCredentialsEndpoint string

// GetCredentialsEndpoint returns the endpoint.
func (p WithCredentialsEndpoint) GetCredentialsEndpoint() (string, error) {
	return string(p), nil
}

// GetCredentialsEndpoint searchds the Configs for a CredentialsEndpointProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func GetCredentialsEndpoint(configs Configs) (string, bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(CredentialsEndpointProvider); ok {
			v, err := p.GetCredentialsEndpoint()
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

// ContainerCredentialsEndpointPathProvider provides access to the credentials endpoint path
// external configuration value.
type ContainerCredentialsEndpointPathProvider interface {
	GetContainerCredentialsEndpointPath() (string, error)
}

// WithContainerCredentialsEndpointPath provides wrapping of a string to satisfy the
// ContainerCredentialsEndpointPathProvider interface.
type WithContainerCredentialsEndpointPath string

// GetContainerCredentialsEndpointPath returns the endpoint path.
func (p WithContainerCredentialsEndpointPath) GetContainerCredentialsEndpointPath() (string, error) {
	return string(p), nil
}

// GetContainerCredentialsEndpointPath searchds the Configs for a
// ContainerCredentialsEndpointPathProvider and returns the value if found.
// Returns an error if a provider fails before a
// value is found.
func GetContainerCredentialsEndpointPath(configs Configs) (string, bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(ContainerCredentialsEndpointPathProvider); ok {
			v, err := p.GetContainerCredentialsEndpointPath()
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

// AssumeRoleConfigProvider provides access to the assume role config
// external configuration value.
type AssumeRoleConfigProvider interface {
	GetAssumeRoleConfig() (AssumeRoleConfig, error)
}

// WithAssumeRoleConfig provides wrapping of a string to satisfy the
// AssumeRoleConfigProvider interface.
type WithAssumeRoleConfig AssumeRoleConfig

// GetAssumeRoleConfig returns the AssumeRoleConfig.
func (p WithAssumeRoleConfig) GetAssumeRoleConfig() (AssumeRoleConfig, error) {
	return AssumeRoleConfig(p), nil
}

// GetAssumeRoleConfig searchds the Configs for a AssumeRoleConfigProvider
// and returns the value if found. Returns an error if a provider fails before a
// value is found.
func GetAssumeRoleConfig(configs Configs) (AssumeRoleConfig, bool, error) {
	for _, cfg := range configs {
		if p, ok := cfg.(AssumeRoleConfigProvider); ok {
			v, err := p.GetAssumeRoleConfig()
			if err != nil {
				return AssumeRoleConfig{}, false, err
			}
			if len(v.RoleARN) > 0 && v.Source != nil {
				return v, true, nil
			}
		}
	}

	return AssumeRoleConfig{}, false, nil
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

// GetMFATokenFunc searchds the Configs for a MFATokenFuncProvider
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
	Client *ec2metadata.Client
}

// GetRegion attempts to retreive the region from EC2 Metadata service.
func (p WithEC2MetadataRegion) GetRegion() (string, error) {
	return p.Client.Region()
}

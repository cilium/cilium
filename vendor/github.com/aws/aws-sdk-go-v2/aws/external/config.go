package external

import (
	"github.com/aws/aws-sdk-go-v2/aws"
)

// DefaultConfigLoaders are a slice of functions that will read external configuration
// sources for configuration values. These values are read by the AWSConfigResolvers
// using interfaces to extract specific information from the external configuration.
var DefaultConfigLoaders = []ConfigLoader{
	LoadEnvConfig,
	LoadSharedConfigIgnoreNotExist,
}

// DefaultAWSConfigResolvers are a slice of functions that will resolve external
// configuration values into AWS configuration values.
//
// This will setup the AWS configuration's Region,
var DefaultAWSConfigResolvers = []AWSConfigResolver{
	ResolveDefaultAWSConfig,
	ResolveCustomCABundle,

	ResolveRegion,

	ResolveFallbackEC2Credentials, // Initial defauilt credentails provider.
	ResolveCredentialsValue,
	ResolveEndpointCredentials,
	ResolveContainerEndpointPathCredentials, // TODO is this order right?
	ResolveAssumeRoleCredentials,
}

// A Config represents a generic configuration value or set of values. This type
// will be used by the AWSConfigResolvers to extract
//
// General the Config type will use type assertion against the Provider interfaces
// to extract specific data from the Config.
type Config interface{}

// A ConfigLoader is used to load external configuration data and returns it as
// a generic Config type.
//
// The loader should return an error if it fails to load the external configuration
// or the configuration data is malformed, or required components missing.
type ConfigLoader func(Configs) (Config, error)

// An AWSConfigResolver will extract configuration data from the Configs slice
// using the provider interfaces to extract specific functionality. The extracted
// configuration values will be written to the AWS Config value.
//
// The resolver should return an error if it it fails to extract the data, the
// data is malformed, or incomplete.
type AWSConfigResolver func(cfg *aws.Config, configs Configs) error

// Configs is a slice of Config values. These values will be used by the
// AWSConfigResolvers to extract external configuration values to populate the
// AWS Config type.
//
// Use AppendFromLoaders to add additional external Config values that are
// loaded from external sources.
//
// Use ResolveAWSConfig after external Config values have been added or loaded
// to extract the loaded configuration values into the AWS Config.
type Configs []Config

// AppendFromLoaders iterates over the slice of loaders passed in calling each
// loader function in order. The external config value returned by the loader
// will be added to the returned Configs slice.
//
// If a loader returns an error this method will stop iterating and return
// that error.
func (cs Configs) AppendFromLoaders(loaders []ConfigLoader) (Configs, error) {
	for _, fn := range loaders {
		cfg, err := fn(cs)
		if err != nil {
			return nil, err
		}

		cs = append(cs, cfg)
	}

	return cs, nil
}

// ResolveAWSConfig returns a AWS configuration populated with values by calling
// the resolvers slice passed in. Each resolver is called in order. Any resolver
// may overwrite the AWs Configuration value of a previous resolver.
//
// If an resolver returns an error this method will return that error, and stop
// iterating over the resolvers.
func (cs Configs) ResolveAWSConfig(resolvers []AWSConfigResolver) (aws.Config, error) {
	var cfg aws.Config

	for _, fn := range resolvers {
		if err := fn(&cfg, cs); err != nil {
			// TODO provide better error?
			return aws.Config{}, err
		}
	}

	return cfg, nil
}

// LoadDefaultAWSConfig reads the SDK's default external configurations, and
// populates an AWS Config with the values from the external configurations.
//
// An optional variadic set of additional Config values can be provided as input
// that will be prepended to the Configs slice. Use this to add custom configuration.
// The custom configurations must satisfy the respective providers for their data
// or the custom data will be ignored by the resolvers and config loaders.
//
//    cfg, err := external.LoadDefaultAWSConfig(
//       WithSharedConfigProfile("test-profile"),
//    )
//    if err != nil {
//       panic(fmt.Sprintf("failed loading config, %v", err))
//    }
//
//
// The default configuration sources are:
// * Environment Variables
// * Shared Configuration and Shared Credentials files.
func LoadDefaultAWSConfig(configs ...Config) (aws.Config, error) {
	var cfgs Configs
	cfgs = append(cfgs, configs...)

	cfgs, err := cfgs.AppendFromLoaders(DefaultConfigLoaders)
	if err != nil {
		return aws.Config{}, err
	}

	return cfgs.ResolveAWSConfig(DefaultAWSConfigResolvers)
}

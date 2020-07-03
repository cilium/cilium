package external

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws/defaults"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
)

// ResolveDefaultAWSConfig will write default configuration values into the cfg
// value. It will write the default values, overwriting any previous value.
//
// This should be used as the first resolver in the slice of resolvers when
// resolving external configuration.
func ResolveDefaultAWSConfig(cfg *aws.Config, configs Configs) error {
	*cfg = defaults.Config()
	return nil
}

// ResolveCustomCABundle extracts the first instance of a custom CA bundle filename
// from the external configurations. It will update the HTTP Client's builder
// to be configured with the custom CA bundle.
//
// Config provider used:
// * CustomCABundleProvider
func ResolveCustomCABundle(cfg *aws.Config, configs Configs) error {
	pemCerts, found, err := GetCustomCABundle(configs)
	if err != nil {
		// TODO error handling, What is the best way to handle this?
		// capture previous errors continue. error out if all errors
		return err
	}
	if !found {
		return nil
	}

	type withTransportOptions interface {
		WithTransportOptions(...func(*http.Transport)) aws.HTTPClient
	}

	trOpts, ok := cfg.HTTPClient.(withTransportOptions)
	if !ok {
		return fmt.Errorf("unable to add custom RootCAs HTTPClient, "+
			"has no WithTransportOptions, %T", cfg.HTTPClient)
	}

	var appendErr error
	client := trOpts.WithTransportOptions(func(tr *http.Transport) {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		if tr.TLSClientConfig.RootCAs == nil {
			tr.TLSClientConfig.RootCAs = x509.NewCertPool()
		}
		if !tr.TLSClientConfig.RootCAs.AppendCertsFromPEM(pemCerts) {
			appendErr = awserr.New("LoadCustomCABundleError",
				"failed to load custom CA bundle PEM file", nil)
		}
	})
	if appendErr != nil {
		return appendErr
	}

	cfg.HTTPClient = client
	return err
}

// ResolveRegion extracts the first instance of a Region from the Configs slice.
//
// Config providers used:
// * RegionProvider
func ResolveRegion(cfg *aws.Config, configs Configs) error {
	v, found, err := GetRegion(configs)
	if err != nil {
		// TODO error handling, What is the best way to handle this?
		// capture previous errors continue. error out if all errors
		return err
	}
	if !found {
		return nil
	}

	cfg.Region = v
	return nil
}

// ResolveEnableEndpointDiscovery will configure the AWS config for Endpoint Discovery
// based on the first value discovered from the provided slice of configs.
func ResolveEnableEndpointDiscovery(cfg *aws.Config, configs Configs) error {
	endpointDiscovery, found, err := GetEnableEndpointDiscovery(configs)
	if err != nil {
		return err
	}

	if !found {
		return nil
	}

	cfg.EnableEndpointDiscovery = endpointDiscovery

	return nil
}

// ResolveHandlersFunc will configure the AWS config Handler chain using the resolved
// handlers function if provided.
func ResolveHandlersFunc(cfg *aws.Config, configs Configs) error {
	handlersFunc, found, err := GetHandlersFunc(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.Handlers = handlersFunc(cfg.Handlers)

	return nil
}

// ResolveEndpointResolverFunc extracts the first instance of a EndpointResolverFunc from the config slice
// and sets the functions result on the aws.Config.EndpointResolver
func ResolveEndpointResolverFunc(cfg *aws.Config, configs Configs) error {
	endpointResolverFunc, found, err := GetEndpointResolverFunc(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.EndpointResolver = endpointResolverFunc(cfg.EndpointResolver)

	return nil
}

// ResolveDefaultRegion extracts the first instance of a default region and sets `aws.Config.Region` to the default
// region if region had not been resolved from other sources.
func ResolveDefaultRegion(cfg *aws.Config, configs Configs) error {
	if len(cfg.Region) > 0 {
		return nil
	}

	region, found, err := GetDefaultRegion(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.Region = region

	return nil
}

type ec2MetadataRegionClient interface {
	Region(context.Context) (string, error)
}

// newEC2MetadataClient is the EC2 instance metadata service client, allows for swapping during testing
var newEC2MetadataClient = func(cfg aws.Config) ec2MetadataRegionClient {
	return ec2metadata.New(cfg)
}

// ResolveEC2Region attempts to resolve the region using the EC2 instance metadata service. If region is already set on
// the config no lookup occurs. If an error is returned the service is assumed unavailable.
func ResolveEC2Region(cfg *aws.Config, _ Configs) error {
	if len(cfg.Region) > 0 {
		return nil
	}

	client := newEC2MetadataClient(*cfg)

	// TODO: What does context look like with external config loading and how to handle the impact to service client config loading
	region, err := client.Region(context.Background())
	if err != nil {
		return nil
	}

	cfg.Region = region

	return nil
}

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/awslabs/smithy-go/logging"
)

// resolveDefaultAWSConfig will write default configuration values into the cfg
// value. It will write the default values, overwriting any previous value.
//
// This should be used as the first resolver in the slice of resolvers when
// resolving external configuration.
func resolveDefaultAWSConfig(cfg *aws.Config, cfgs configs) error {
	*cfg = aws.Config{
		Credentials: aws.AnonymousCredentials{},
		Logger:      logging.NewStandardLogger(os.Stderr),
	}
	return nil
}

// resolveCustomCABundle extracts the first instance of a custom CA bundle filename
// from the external configurations. It will update the HTTP Client's builder
// to be configured with the custom CA bundle.
//
// Config provider used:
// * CustomCABundleProvider
func resolveCustomCABundle(cfg *aws.Config, cfgs configs) error {
	pemCerts, found, err := getCustomCABundle(cfgs)
	if err != nil {
		// TODO error handling, What is the best way to handle this?
		// capture previous errors continue. error out if all errors
		return err
	}
	if !found {
		return nil
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = awshttp.NewBuildableClient()
	}

	trOpts, ok := cfg.HTTPClient.(*awshttp.BuildableClient)
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
			appendErr = fmt.Errorf("failed to load custom CA bundle PEM file")
		}
	})
	if appendErr != nil {
		return appendErr
	}

	cfg.HTTPClient = client
	return err
}

// resolveRegion extracts the first instance of a Region from the configs slice.
//
// Config providers used:
// * RegionProvider
func resolveRegion(cfg *aws.Config, configs configs) error {
	v, found, err := getRegion(configs)
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

// resolveDefaultRegion extracts the first instance of a default region and sets `aws.Config.Region` to the default
// region if region had not been resolved from other sources.
func resolveDefaultRegion(cfg *aws.Config, configs configs) error {
	if len(cfg.Region) > 0 {
		return nil
	}

	region, found, err := getDefaultRegion(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.Region = region

	return nil
}

// resolveHTTPClient extracts the first instance of a HTTPClient and sets `aws.Config.HTTPClient` to the HTTPClient instance
// if one has not been resolved from other sources.
func resolveHTTPClient(cfg *aws.Config, configs configs) error {
	c, found, err := getHTTPClient(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.HTTPClient = c
	return nil
}

// resolveAPIOptions extracts the first instance of APIOptions and sets `aws.Config.APIOptions` to the resolved API options
// if one has not been resolved from other sources.
func resolveAPIOptions(cfg *aws.Config, configs configs) error {
	o, found, err := getAPIOptions(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.APIOptions = o

	return nil
}

// resolveEndpointResolver extracts the first instance of a EndpointResolverFunc from the config slice
// and sets the functions result on the aws.Config.EndpointResolver
func resolveEndpointResolver(cfg *aws.Config, configs configs) error {
	endpointResolver, found, err := getEndpointResolver(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.EndpointResolver = endpointResolver

	return nil
}

func resolveLogger(cfg *aws.Config, configs configs) error {
	logger, found, err := getLogger(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.Logger = logger

	return nil
}

func resolveClientLogMode(cfg *aws.Config, configs configs) error {
	mode, found, err := getClientLogMode(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.ClientLogMode = mode

	return nil
}

func resolveRetryer(cfg *aws.Config, configs configs) error {
	retryer, found, err := getRetryer(configs)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	cfg.Retryer = retryer

	return nil
}

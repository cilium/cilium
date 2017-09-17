/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azure

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/version"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/azure-sdk-for-go/arm/disk"
	"github.com/Azure/azure-sdk-for-go/arm/network"
	"github.com/Azure/azure-sdk-for-go/arm/storage"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"golang.org/x/crypto/pkcs12"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	// CloudProviderName is the value used for the --cloud-provider flag
	CloudProviderName      = "azure"
	rateLimitQPSDefault    = 1.0
	rateLimitBucketDefault = 5
	backoffRetriesDefault  = 6
	backoffExponentDefault = 1.5
	backoffDurationDefault = 5 // in seconds
	backoffJitterDefault   = 1.0
)

// Config holds the configuration parsed from the --cloud-config flag
// All fields are required unless otherwise specified
type Config struct {
	// The cloud environment identifier. Takes values from https://github.com/Azure/go-autorest/blob/ec5f4903f77ed9927ac95b19ab8e44ada64c1356/autorest/azure/environments.go#L13
	Cloud string `json:"cloud" yaml:"cloud"`
	// The AAD Tenant ID for the Subscription that the cluster is deployed in
	TenantID string `json:"tenantId" yaml:"tenantId"`
	// The ID of the Azure Subscription that the cluster is deployed in
	SubscriptionID string `json:"subscriptionId" yaml:"subscriptionId"`
	// The name of the resource group that the cluster is deployed in
	ResourceGroup string `json:"resourceGroup" yaml:"resourceGroup"`
	// The location of the resource group that the cluster is deployed in
	Location string `json:"location" yaml:"location"`
	// The name of the VNet that the cluster is deployed in
	VnetName string `json:"vnetName" yaml:"vnetName"`
	// The name of the resource group that the Vnet is deployed in
	VnetResourceGroup string `json:"vnetResourceGroup" yaml:"vnetResourceGroup"`
	// The name of the subnet that the cluster is deployed in
	SubnetName string `json:"subnetName" yaml:"subnetName"`
	// The name of the security group attached to the cluster's subnet
	SecurityGroupName string `json:"securityGroupName" yaml:"securityGroupName"`
	// (Optional in 1.6) The name of the route table attached to the subnet that the cluster is deployed in
	RouteTableName string `json:"routeTableName" yaml:"routeTableName"`
	// (Optional) The name of the availability set that should be used as the load balancer backend
	// If this is set, the Azure cloudprovider will only add nodes from that availability set to the load
	// balancer backend pool. If this is not set, and multiple agent pools (availability sets) are used, then
	// the cloudprovider will try to add all nodes to a single backend pool which is forbidden.
	// In other words, if you use multiple agent pools (availability sets), you MUST set this field.
	PrimaryAvailabilitySetName string `json:"primaryAvailabilitySetName" yaml:"primaryAvailabilitySetName"`

	// The ClientID for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientID string `json:"aadClientId" yaml:"aadClientId"`
	// The ClientSecret for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientSecret string `json:"aadClientSecret" yaml:"aadClientSecret"`
	// The path of a client certificate for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientCertPath string `json:"aadClientCertPath" yaml:"aadClientCertPath"`
	// The password of the client certificate for an AAD application with RBAC access to talk to Azure RM APIs
	AADClientCertPassword string `json:"aadClientCertPassword" yaml:"aadClientCertPassword"`
	// Enable exponential backoff to manage resource request retries
	CloudProviderBackoff bool `json:"cloudProviderBackoff" yaml:"cloudProviderBackoff"`
	// Backoff retry limit
	CloudProviderBackoffRetries int `json:"cloudProviderBackoffRetries" yaml:"cloudProviderBackoffRetries"`
	// Backoff exponent
	CloudProviderBackoffExponent float64 `json:"cloudProviderBackoffExponent" yaml:"cloudProviderBackoffExponent"`
	// Backoff duration
	CloudProviderBackoffDuration int `json:"cloudProviderBackoffDuration" yaml:"cloudProviderBackoffDuration"`
	// Backoff jitter
	CloudProviderBackoffJitter float64 `json:"cloudProviderBackoffJitter" yaml:"cloudProviderBackoffJitter"`
	// Enable rate limiting
	CloudProviderRateLimit bool `json:"cloudProviderRateLimit" yaml:"cloudProviderRateLimit"`
	// Rate limit QPS
	CloudProviderRateLimitQPS float32 `json:"cloudProviderRateLimitQPS" yaml:"cloudProviderRateLimitQPS"`
	// Rate limit Bucket Size
	CloudProviderRateLimitBucket int `json:"cloudProviderRateLimitBucket" yaml:"cloudProviderRateLimitBucket"`

	// Use instance metadata service where possible
	UseInstanceMetadata bool `json:"useInstanceMetadata" yaml:"useInstanceMetadata"`

	// Use managed service identity for the virtual machine to access Azure ARM APIs
	UseManagedIdentityExtension bool `json:"useManagedIdentityExtension"`
}

// Cloud holds the config and clients
type Cloud struct {
	Config
	Environment              azure.Environment
	RoutesClient             network.RoutesClient
	SubnetsClient            network.SubnetsClient
	InterfacesClient         network.InterfacesClient
	RouteTablesClient        network.RouteTablesClient
	LoadBalancerClient       network.LoadBalancersClient
	PublicIPAddressesClient  network.PublicIPAddressesClient
	SecurityGroupsClient     network.SecurityGroupsClient
	VirtualMachinesClient    compute.VirtualMachinesClient
	StorageAccountClient     storage.AccountsClient
	DisksClient              disk.DisksClient
	operationPollRateLimiter flowcontrol.RateLimiter
	resourceRequestBackoff   wait.Backoff
	metadata                 *InstanceMetadata

	*BlobDiskController
	*ManagedDiskController
	*controllerCommon
}

func init() {
	cloudprovider.RegisterCloudProvider(CloudProviderName, NewCloud)
}

// decodePkcs12 decodes a PKCS#12 client certificate by extracting the public certificate and
// the private RSA key
func decodePkcs12(pkcs []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, certificate, err := pkcs12.Decode(pkcs, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding the PKCS#12 client certificate: %v", err)
	}
	rsaPrivateKey, isRsaKey := privateKey.(*rsa.PrivateKey)
	if !isRsaKey {
		return nil, nil, fmt.Errorf("PKCS#12 certificate must contain a RSA private key")
	}

	return certificate, rsaPrivateKey, nil
}

// GetServicePrincipalToken creates a new service principal token based on the configuration
func GetServicePrincipalToken(config *Config, env *azure.Environment) (*adal.ServicePrincipalToken, error) {
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, config.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	if config.UseManagedIdentityExtension {
		glog.V(2).Infoln("azure: using managed identity extension to retrieve access token")
		return adal.NewServicePrincipalTokenFromMSI(
			*oauthConfig,
			env.ServiceManagementEndpoint)
	}

	if len(config.AADClientSecret) > 0 {
		glog.V(2).Infoln("azure: using client_id+client_secret to retrieve access token")
		return adal.NewServicePrincipalToken(
			*oauthConfig,
			config.AADClientID,
			config.AADClientSecret,
			env.ServiceManagementEndpoint)
	}

	if len(config.AADClientCertPath) > 0 && len(config.AADClientCertPassword) > 0 {
		glog.V(2).Infoln("azure: using jwt client_assertion (client_cert+client_private_key) to retrieve access token")
		certData, err := ioutil.ReadFile(config.AADClientCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading the client certificate from file %s: %v", config.AADClientCertPath, err)
		}
		certificate, privateKey, err := decodePkcs12(certData, config.AADClientCertPassword)
		if err != nil {
			return nil, fmt.Errorf("decoding the client certificate: %v", err)
		}
		return adal.NewServicePrincipalTokenFromCertificate(
			*oauthConfig,
			config.AADClientID,
			certificate,
			privateKey,
			env.ServiceManagementEndpoint)
	}

	return nil, fmt.Errorf("No credentials provided for AAD application %s", config.AADClientID)
}

// NewCloud returns a Cloud with initialized clients
func NewCloud(configReader io.Reader) (cloudprovider.Interface, error) {
	config, env, err := ParseConfig(configReader)
	if err != nil {
		return nil, err
	}
	az := Cloud{
		Config:      *config,
		Environment: *env,
	}

	servicePrincipalToken, err := GetServicePrincipalToken(config, env)
	if err != nil {
		return nil, err
	}

	az.SubnetsClient = network.NewSubnetsClient(az.SubscriptionID)
	az.SubnetsClient.BaseURI = az.Environment.ResourceManagerEndpoint
	az.SubnetsClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	az.SubnetsClient.PollingDelay = 5 * time.Second
	configureUserAgent(&az.SubnetsClient.Client)

	az.RouteTablesClient = network.NewRouteTablesClient(az.SubscriptionID)
	az.RouteTablesClient.BaseURI = az.Environment.ResourceManagerEndpoint
	az.RouteTablesClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	az.RouteTablesClient.PollingDelay = 5 * time.Second
	configureUserAgent(&az.RouteTablesClient.Client)

	az.RoutesClient = network.NewRoutesClient(az.SubscriptionID)
	az.RoutesClient.BaseURI = az.Environment.ResourceManagerEndpoint
	az.RoutesClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	az.RoutesClient.PollingDelay = 5 * time.Second
	configureUserAgent(&az.RoutesClient.Client)

	az.InterfacesClient = network.NewInterfacesClient(az.SubscriptionID)
	az.InterfacesClient.BaseURI = az.Environment.ResourceManagerEndpoint
	az.InterfacesClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	az.InterfacesClient.PollingDelay = 5 * time.Second
	configureUserAgent(&az.InterfacesClient.Client)

	az.LoadBalancerClient = network.NewLoadBalancersClient(az.SubscriptionID)
	az.LoadBalancerClient.BaseURI = az.Environment.ResourceManagerEndpoint
	az.LoadBalancerClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	az.LoadBalancerClient.PollingDelay = 5 * time.Second
	configureUserAgent(&az.LoadBalancerClient.Client)

	az.VirtualMachinesClient = compute.NewVirtualMachinesClient(az.SubscriptionID)
	az.VirtualMachinesClient.BaseURI = az.Environment.ResourceManagerEndpoint
	az.VirtualMachinesClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	az.VirtualMachinesClient.PollingDelay = 5 * time.Second
	configureUserAgent(&az.VirtualMachinesClient.Client)

	az.PublicIPAddressesClient = network.NewPublicIPAddressesClient(az.SubscriptionID)
	az.PublicIPAddressesClient.BaseURI = az.Environment.ResourceManagerEndpoint
	az.PublicIPAddressesClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	az.PublicIPAddressesClient.PollingDelay = 5 * time.Second
	configureUserAgent(&az.PublicIPAddressesClient.Client)

	az.SecurityGroupsClient = network.NewSecurityGroupsClient(az.SubscriptionID)
	az.SecurityGroupsClient.BaseURI = az.Environment.ResourceManagerEndpoint
	az.SecurityGroupsClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	az.SecurityGroupsClient.PollingDelay = 5 * time.Second
	configureUserAgent(&az.SecurityGroupsClient.Client)

	az.StorageAccountClient = storage.NewAccountsClientWithBaseURI(az.Environment.ResourceManagerEndpoint, az.SubscriptionID)
	az.StorageAccountClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	configureUserAgent(&az.StorageAccountClient.Client)

	az.DisksClient = disk.NewDisksClientWithBaseURI(az.Environment.ResourceManagerEndpoint, az.SubscriptionID)
	az.DisksClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	configureUserAgent(&az.DisksClient.Client)

	// Conditionally configure rate limits
	if az.CloudProviderRateLimit {
		// Assign rate limit defaults if no configuration was passed in
		if az.CloudProviderRateLimitQPS == 0 {
			az.CloudProviderRateLimitQPS = rateLimitQPSDefault
		}
		if az.CloudProviderRateLimitBucket == 0 {
			az.CloudProviderRateLimitBucket = rateLimitBucketDefault
		}
		az.operationPollRateLimiter = flowcontrol.NewTokenBucketRateLimiter(
			az.CloudProviderRateLimitQPS,
			az.CloudProviderRateLimitBucket)
		glog.V(2).Infof("Azure cloudprovider using rate limit config: QPS=%d, bucket=%d",
			az.CloudProviderRateLimitQPS,
			az.CloudProviderRateLimitBucket)
	} else {
		// if rate limits are configured off, az.operationPollRateLimiter.Accept() is a no-op
		az.operationPollRateLimiter = flowcontrol.NewFakeAlwaysRateLimiter()
	}

	// Conditionally configure resource request backoff
	if az.CloudProviderBackoff {
		// Assign backoff defaults if no configuration was passed in
		if az.CloudProviderBackoffRetries == 0 {
			az.CloudProviderBackoffRetries = backoffRetriesDefault
		}
		if az.CloudProviderBackoffExponent == 0 {
			az.CloudProviderBackoffExponent = backoffExponentDefault
		}
		if az.CloudProviderBackoffDuration == 0 {
			az.CloudProviderBackoffDuration = backoffDurationDefault
		}
		if az.CloudProviderBackoffJitter == 0 {
			az.CloudProviderBackoffJitter = backoffJitterDefault
		}
		az.resourceRequestBackoff = wait.Backoff{
			Steps:    az.CloudProviderBackoffRetries,
			Factor:   az.CloudProviderBackoffExponent,
			Duration: time.Duration(az.CloudProviderBackoffDuration) * time.Second,
			Jitter:   az.CloudProviderBackoffJitter,
		}
		glog.V(2).Infof("Azure cloudprovider using retry backoff: retries=%d, exponent=%f, duration=%d, jitter=%f",
			az.CloudProviderBackoffRetries,
			az.CloudProviderBackoffExponent,
			az.CloudProviderBackoffDuration,
			az.CloudProviderBackoffJitter)
	}

	az.metadata = NewInstanceMetadata()

	if err := initDiskControllers(&az); err != nil {
		return nil, err
	}
	return &az, nil
}

// ParseConfig returns a parsed configuration and azure.Environment for an Azure cloudprovider config file
func ParseConfig(configReader io.Reader) (*Config, *azure.Environment, error) {
	var config Config
	var env azure.Environment

	if configReader == nil {
		return &config, &env, nil
	}

	configContents, err := ioutil.ReadAll(configReader)
	if err != nil {
		return nil, nil, err
	}
	err = yaml.Unmarshal(configContents, &config)
	if err != nil {
		return nil, nil, err
	}

	if config.Cloud == "" {
		env = azure.PublicCloud
	} else {
		env, err = azure.EnvironmentFromName(config.Cloud)
		if err != nil {
			return nil, nil, err
		}
	}
	return &config, &env, nil
}

// Initialize passes a Kubernetes clientBuilder interface to the cloud provider
func (az *Cloud) Initialize(clientBuilder controller.ControllerClientBuilder) {}

// LoadBalancer returns a balancer interface. Also returns true if the interface is supported, false otherwise.
func (az *Cloud) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return az, true
}

// Instances returns an instances interface. Also returns true if the interface is supported, false otherwise.
func (az *Cloud) Instances() (cloudprovider.Instances, bool) {
	return az, true
}

// Zones returns a zones interface. Also returns true if the interface is supported, false otherwise.
func (az *Cloud) Zones() (cloudprovider.Zones, bool) {
	return az, true
}

// Clusters returns a clusters interface.  Also returns true if the interface is supported, false otherwise.
func (az *Cloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// Routes returns a routes interface along with whether the interface is supported.
func (az *Cloud) Routes() (cloudprovider.Routes, bool) {
	return az, true
}

// ScrubDNS provides an opportunity for cloud-provider-specific code to process DNS settings for pods.
func (az *Cloud) ScrubDNS(nameservers, searches []string) (nsOut, srchOut []string) {
	return nameservers, searches
}

// HasClusterID returns true if the cluster has a clusterID
func (az *Cloud) HasClusterID() bool {
	return true
}

// ProviderName returns the cloud provider ID.
func (az *Cloud) ProviderName() string {
	return CloudProviderName
}

// configureUserAgent configures the autorest client with a user agent that
// includes "kubernetes" and the full kubernetes git version string
// example:
// Azure-SDK-for-Go/7.0.1-beta arm-network/2016-09-01; kubernetes-cloudprovider/v1.7.0-alpha.2.711+a2fadef8170bb0-dirty;
func configureUserAgent(client *autorest.Client) {
	k8sVersion := version.Get().GitVersion
	client.UserAgent = fmt.Sprintf("%s; kubernetes-cloudprovider/%s", client.UserAgent, k8sVersion)
}

func initDiskControllers(az *Cloud) error {
	// Common controller contains the function
	// needed by both blob disk and managed disk controllers

	common := &controllerCommon{
		aadResourceEndPoint:   az.Environment.ServiceManagementEndpoint,
		clientID:              az.AADClientID,
		clientSecret:          az.AADClientSecret,
		location:              az.Location,
		storageEndpointSuffix: az.Environment.StorageEndpointSuffix,
		managementEndpoint:    az.Environment.ResourceManagerEndpoint,
		resourceGroup:         az.ResourceGroup,
		tenantID:              az.TenantID,
		tokenEndPoint:         az.Environment.ActiveDirectoryEndpoint,
		subscriptionID:        az.SubscriptionID,
		cloud:                 az,
	}

	// BlobDiskController: contains the function needed to
	// create/attach/detach/delete blob based (unmanaged disks)
	blobController, err := newBlobDiskController(common)
	if err != nil {
		return fmt.Errorf("AzureDisk -  failed to init Blob Disk Controller with error (%s)", err.Error())
	}

	// ManagedDiskController: contains the functions needed to
	// create/attach/detach/delete managed disks
	managedController, err := newManagedDiskController(common)
	if err != nil {
		return fmt.Errorf("AzureDisk -  failed to init Managed  Disk Controller with error (%s)", err.Error())
	}

	az.BlobDiskController = blobController
	az.ManagedDiskController = managedController
	az.controllerCommon = common

	return nil
}

package credentials

import (
	"fmt"
	"os"
	"strings"
)

type DefaultCredentialsProvider struct {
	providerChain    []CredentialsProvider
	lastUsedProvider CredentialsProvider
}

func NewDefaultCredentialsProvider() (provider *DefaultCredentialsProvider) {
	providers := []CredentialsProvider{}

	// Add static ak or sts credentials provider
	providers = append(providers, NewEnvironmentVariableCredentialsProvider())

	// oidc check
	oidcProvider, err := NewOIDCCredentialsProviderBuilder().Build()
	if err == nil {
		providers = append(providers, oidcProvider)
	}

	// cli credentials provider
	providers = append(providers, NewCLIProfileCredentialsProviderBuilder().Build())

	// profile credentials provider
	// providers = append(providers)
	providers = append(providers, NewProfileCredentialsProviderBuilder().Build())

	// Add IMDS
	if os.Getenv("ALIBABA_CLOUD_ECS_METADATA") != "" {
		ecsRamRoleProvider := NewECSRAMRoleCredentialsProvider(os.Getenv("ALIBABA_CLOUD_ECS_METADATA"))
		providers = append(providers, ecsRamRoleProvider)
	}

	// TODO: ALIBABA_CLOUD_CREDENTIALS_URI check

	return &DefaultCredentialsProvider{
		providerChain: providers,
	}
}

func (provider *DefaultCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	if provider.lastUsedProvider != nil {
		cc, err = provider.lastUsedProvider.GetCredentials()
		if err != nil {
			return
		}
		cc.ProviderName = fmt.Sprintf("%s/%s", provider.GetProviderName(), provider.lastUsedProvider.GetProviderName())
		return
	}

	errors := []string{}
	for _, p := range provider.providerChain {
		provider.lastUsedProvider = p
		cc, err = p.GetCredentials()

		if err != nil {
			errors = append(errors, err.Error())
			// 如果有错误，进入下一个获取过程
			continue
		}

		if cc != nil {
			cc.ProviderName = fmt.Sprintf("%s/%s", provider.GetProviderName(), p.GetProviderName())
			return
		}
	}

	err = fmt.Errorf("unable to get credentials from any of the providers in the chain: %s", strings.Join(errors, ", "))
	return
}

func (provider *DefaultCredentialsProvider) GetProviderName() string {
	return "default"
}

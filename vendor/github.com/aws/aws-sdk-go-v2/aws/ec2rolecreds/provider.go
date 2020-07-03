package ec2rolecreds

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
)

// ProviderName provides a name of EC2Role provider
const ProviderName = "EC2RoleProvider"

// A Provider retrieves credentials from the EC2 service, and keeps track if
// those credentials are expired.
//
// The New function must be used to create the Provider.
//
//     p := &ec2rolecreds.New(ec2metadata.New(options))
//
//     // Expire the credentials 10 minutes before IAM states they should. Proactivily
//     // refreshing the credentials.
//     p.ExpiryWindow = 10 * time.Minute
type Provider struct {
	aws.SafeCredentialsProvider

	// Required EC2Metadata client to use when connecting to EC2 metadata service.
	client *ec2metadata.Client

	options ProviderOptions
}

// ProviderOptions is a list of user settable options for setting the behavior of the Provider.
type ProviderOptions struct {
	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	ExpiryWindow time.Duration
}

// New returns an initialized Provider value configured to retrieve
// credentials from EC2 Instance Metadata service.
func New(client *ec2metadata.Client, options ...func(*ProviderOptions)) *Provider {
	p := &Provider{}

	p.client = client
	p.RetrieveFn = p.retrieveFn

	for _, option := range options {
		option(&p.options)
	}

	return p
}

// Retrieve retrieves credentials from the EC2 service.
// Error will be returned if the request fails, or unable to extract
// the desired credentials.
func (p *Provider) retrieveFn() (aws.Credentials, error) {
	credsList, err := requestCredList(context.Background(), p.client)
	if err != nil {
		return aws.Credentials{}, err
	}

	if len(credsList) == 0 {
		return aws.Credentials{},
			awserr.New("EmptyEC2RoleList", "empty EC2 Role list", nil)
	}
	credsName := credsList[0]

	roleCreds, err := requestCred(context.Background(), p.client, credsName)
	if err != nil {
		return aws.Credentials{}, err
	}

	creds := aws.Credentials{
		AccessKeyID:     roleCreds.AccessKeyID,
		SecretAccessKey: roleCreds.SecretAccessKey,
		SessionToken:    roleCreds.Token,
		Source:          ProviderName,

		CanExpire: true,
		Expires:   roleCreds.Expiration.Add(-p.options.ExpiryWindow),
	}

	return creds, nil
}

// A ec2RoleCredRespBody provides the shape for unmarshaling credential
// request responses.
type ec2RoleCredRespBody struct {
	// Success State
	Expiration      time.Time
	AccessKeyID     string
	SecretAccessKey string
	Token           string

	// Error state
	Code    string
	Message string
}

const iamSecurityCredsPath = "/iam/security-credentials/"

// requestCredList requests a list of credentials from the EC2 service.
// If there are no credentials, or there is an error making or receiving the request
func requestCredList(ctx context.Context, client *ec2metadata.Client) ([]string, error) {
	resp, err := client.GetMetadata(ctx, iamSecurityCredsPath)
	if err != nil {
		return nil, awserr.New("EC2RoleRequestError", "no EC2 instance role found", err)
	}

	credsList := []string{}
	s := bufio.NewScanner(strings.NewReader(resp))
	for s.Scan() {
		credsList = append(credsList, s.Text())
	}

	if err := s.Err(); err != nil {
		return nil, awserr.New("SerializationError", "failed to read EC2 instance role from metadata service", err)
	}

	return credsList, nil
}

// requestCred requests the credentials for a specific credentials from the EC2 service.
//
// If the credentials cannot be found, or there is an error reading the response
// and error will be returned.
func requestCred(ctx context.Context, client *ec2metadata.Client, credsName string) (ec2RoleCredRespBody, error) {
	resp, err := client.GetMetadata(ctx, path.Join(iamSecurityCredsPath, credsName))
	if err != nil {
		return ec2RoleCredRespBody{},
			awserr.New("EC2RoleRequestError",
				fmt.Sprintf("failed to get %s EC2 instance role credentials", credsName),
				err)
	}

	respCreds := ec2RoleCredRespBody{}
	if err := json.NewDecoder(strings.NewReader(resp)).Decode(&respCreds); err != nil {
		return ec2RoleCredRespBody{},
			awserr.New("SerializationError",
				fmt.Sprintf("failed to decode %s EC2 instance role credentials", credsName),
				err)
	}

	if respCreds.Code != "Success" {
		// If an error code was returned something failed requesting the role.
		return ec2RoleCredRespBody{}, awserr.New(respCreds.Code, respCreds.Message, nil)
	}

	return respCreds, nil
}

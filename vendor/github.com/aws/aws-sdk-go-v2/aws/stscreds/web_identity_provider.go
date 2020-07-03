package stscreds

import (
	"context"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/stsiface"
)

const (
	// ErrCodeWebIdentity will be used as an error code when constructing
	// a new error to be returned during session creation or retrieval.
	ErrCodeWebIdentity = "WebIdentityErr"

	// WebIdentityProviderName is the web identity provider name
	WebIdentityProviderName = "WebIdentityCredentials"
)

// WebIdentityRoleProvider is used to retrieve credentials using
// an OIDC token.
type WebIdentityRoleProvider struct {
	aws.SafeCredentialsProvider

	client stsiface.ClientAPI

	tokenRetriever  IdentityTokenRetriever
	roleARN         string
	roleSessionName string

	options WebIdentityRoleProviderOptions
}

// WebIdentityRoleProviderOptions is a structure of configurable options for WebIdentityRoleProvider
type WebIdentityRoleProviderOptions struct {
	ExpiryWindow time.Duration
	PolicyArns   []sts.PolicyDescriptorType
}

// IdentityTokenRetriever is an interface for retrieving a JWT
type IdentityTokenRetriever interface {
	GetIdentityToken() ([]byte, error)
}

// IdentityTokenFile is for retrieving an identity token from the given file name
type IdentityTokenFile string

// GetIdentityToken retrieves the JWT token from the file and returns the contents as a []byte
func (j IdentityTokenFile) GetIdentityToken() ([]byte, error) {
	b, err := ioutil.ReadFile(string(j))
	if err != nil {
		return nil, fmt.Errorf("unable to read file at %s: %v", string(j), err)
	}

	return b, nil
}

// NewWebIdentityRoleProvider will return a new WebIdentityRoleProvider with the
// provided stsiface.ClientAPI
func NewWebIdentityRoleProvider(svc stsiface.ClientAPI, roleARN, roleSessionName string, tokenRetriever IdentityTokenRetriever, options ...func(*WebIdentityRoleProviderOptions)) *WebIdentityRoleProvider {
	p := &WebIdentityRoleProvider{
		client:          svc,
		tokenRetriever:  tokenRetriever,
		roleARN:         roleARN,
		roleSessionName: roleSessionName,
	}

	p.RetrieveFn = p.retrieveFn

	for _, option := range options {
		option(&p.options)
	}

	return p
}

// retrieve will attempt to assume a role from a token which is located at
// 'WebIdentityTokenFilePath' specified destination and if that is empty an
// error will be returned.
func (p *WebIdentityRoleProvider) retrieveFn() (aws.Credentials, error) {
	b, err := p.tokenRetriever.GetIdentityToken()
	if err != nil {
		return aws.Credentials{}, awserr.New(ErrCodeWebIdentity, "failed to retrieve jwt from provide source", err)
	}

	sessionName := p.roleSessionName
	if len(sessionName) == 0 {
		// session name is used to uniquely identify a session. This simply
		// uses unix time in nanoseconds to uniquely identify sessions.
		sessionName = strconv.FormatInt(sdk.NowTime().UnixNano(), 10)
	}
	req := p.client.AssumeRoleWithWebIdentityRequest(&sts.AssumeRoleWithWebIdentityInput{
		PolicyArns:       p.options.PolicyArns,
		RoleArn:          &p.roleARN,
		RoleSessionName:  &sessionName,
		WebIdentityToken: aws.String(string(b)),
	})

	// InvalidIdentityToken error is a temporary error that can occur
	// when assuming an Role with a JWT web identity token.
	req.Retryer = retry.AddWithErrorCodes(req.Retryer, sts.ErrCodeInvalidIdentityTokenException)
	resp, err := req.Send(context.Background())
	if err != nil {
		return aws.Credentials{}, awserr.New(ErrCodeWebIdentity, "failed to retrieve credentials", err)
	}

	value := aws.Credentials{
		AccessKeyID:     aws.StringValue(resp.Credentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(resp.Credentials.SecretAccessKey),
		SessionToken:    aws.StringValue(resp.Credentials.SessionToken),
		Source:          WebIdentityProviderName,
		CanExpire:       true,
		Expires:         resp.Credentials.Expiration.Add(-p.options.ExpiryWindow),
	}
	return value, nil
}

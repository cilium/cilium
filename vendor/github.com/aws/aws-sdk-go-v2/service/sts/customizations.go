package sts

import "github.com/aws/aws-sdk-go-v2/aws"

func init() {
	initRequest = func(c *Client, r *aws.Request) {
		r.RetryErrorCodes = append(r.RetryErrorCodes, ErrCodeIDPCommunicationErrorException)
	}
}

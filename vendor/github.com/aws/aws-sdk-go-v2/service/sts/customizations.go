package sts

import request "github.com/aws/aws-sdk-go-v2/aws"

func init() {
	initRequest = func(c *STS, r *request.Request) {
		switch r.Operation.Name {
		case opAssumeRoleWithSAML, opAssumeRoleWithWebIdentity:
			r.Handlers.Sign.Clear() // these operations are unsigned
		}
	}
}

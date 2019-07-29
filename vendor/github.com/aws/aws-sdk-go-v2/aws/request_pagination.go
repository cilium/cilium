package aws

import (
	"context"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

// A Pager provides paginating of SDK API operations which are paginatable.
// Generally you should not use this type directly, but use the "Pages" API
// operations method to automatically perform pagination for you. Such as,
// "S3.ListObjectsPages", and "S3.ListObjectsPagesWithContext" methods.
//
// Pagier differs from a Paginator type in that pagination is the type that
// does the pagination between API operations, and Paginator defines the
// configuration that will be used per page request.
//
//     for p.Next() {
//         data := p.CurrentPage().(*s3.ListObjectsOutput)
//         // process the page's data
//     }
//     return p.Err()
//
// See service client API operation Pages methods for examples how the SDK will
// use the Pager type.
type Pager struct {
	// Function to return a Request value for each pagination request.
	// Any configuration or handlers that need to be applied to the request
	// prior to getting the next page should be done here before the request
	// returned.
	//
	// NewRequest should always be built from the same API operations. It is
	// undefined if different API operations are returned on subsequent calls.
	NewRequest func(context.Context) (*Request, error)

	started    bool
	nextTokens []interface{}

	err     error
	curPage interface{}
}

// hasNextPage will return true if Pager is able to determine that the API
// operation has additional pages. False will be returned if there are no more
// pages remaining.
//
// Will always return true if Next has not been called yet.
func (p *Pager) hasNextPage() bool {
	return !(p.started && len(p.nextTokens) == 0)
}

// Err returns the error Pager encountered when retrieving the next page.
func (p *Pager) Err() error {
	return p.err
}

// CurrentPage returns the current page. Page should only be called after a successful
// call to Next. It is undefined what Page will return if Page is called after
// Next returns false.
func (p *Pager) CurrentPage() interface{} {
	return p.curPage
}

// Next will attempt to retrieve the next page for the API operation. When a page
// is retrieved true will be returned. If the page cannot be retrieved, or there
// are no more pages false will be returned.
//
// Use the Page method to retrieve the current page data. The data will need
// to be cast to the API operation's output type.
//
// Use the Err method to determine if an error occurred if Page returns false.
func (p *Pager) Next(ctx context.Context) bool {
	if !p.hasNextPage() {
		return false
	}

	req, err := p.NewRequest(ctx)
	if err != nil {
		p.err = err
		return false
	}

	if p.started {
		for i, intok := range req.Operation.InputTokens {
			awsutil.SetValueAtPath(req.Params, intok, p.nextTokens[i])
		}
	}
	p.started = true

	err = req.Send()
	if err != nil {
		p.err = err
		return false
	}

	p.nextTokens = req.nextPageTokens()
	p.curPage = req.Data

	return true
}

// A Paginator is the configuration data that defines how an API operation
// should be paginated. This type is used by the API service models to define
// the generated pagination config for service APIs.
//
// The Pager type is what provides iterating between pages of an API. It
// is only used to store the token metadata the SDK should use for performing
// pagination.
type Paginator struct {
	InputTokens     []string
	OutputTokens    []string
	LimitToken      string
	TruncationToken string
}

// nextPageTokens returns the tokens to use when asking for the next page of data.
func (r *Request) nextPageTokens() []interface{} {
	if r.Operation.Paginator == nil {
		return nil
	}
	if r.Operation.TruncationToken != "" {
		tr, _ := awsutil.ValuesAtPath(r.Data, r.Operation.TruncationToken)
		if len(tr) == 0 {
			return nil
		}

		switch v := tr[0].(type) {
		case *bool:
			if !BoolValue(v) {
				return nil
			}
		case bool:
			if v == false {
				return nil
			}
		}
	}

	tokens := []interface{}{}
	tokenAdded := false
	for _, outToken := range r.Operation.OutputTokens {
		vs, _ := awsutil.ValuesAtPath(r.Data, outToken)

		if len(vs) == 0 {
			tokens = append(tokens, nil)
			continue
		}
		v := vs[0]

		switch tv := v.(type) {
		case *string:
			if len(StringValue(tv)) == 0 {
				tokens = append(tokens, nil)
				continue
			}
		case string:
			if len(tv) == 0 {
				tokens = append(tokens, nil)
				continue
			}
		}

		tokenAdded = true
		tokens = append(tokens, v)
	}
	if !tokenAdded {
		return nil
	}

	return tokens
}

// Ensure a deprecated item is only logged once instead of each time its used.
func logDeprecatedf(logger Logger, flag *int32, msg string) {
	if logger == nil {
		return
	}
	if atomic.CompareAndSwapInt32(flag, 0, 1) {
		logger.Log(msg)
	}
}

var (
	logDeprecatedHasNextPage int32
	logDeprecatedNextPage    int32
	logDeprecatedEachPage    int32
)

package utils

import (
	. "gopkg.in/check.v1"
	"net/http"
	"net/url"
)

type DumpHttpReqSuite struct {
}

var _ = Suite(&DumpHttpReqSuite{})

type readCloserTestImpl struct {
}

func (r *readCloserTestImpl) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (r *readCloserTestImpl) Close() error {
	return nil
}

//Just to make sure we don't panic, return err and not
//username and pass and cover the function
func (s *DumpHttpReqSuite) TestHttpReqToString(c *C) {
	req := &http.Request{
		URL:    &url.URL{Host: "localhost:2374", Path: "/unittest"},
		Method: "DELETE",
		Cancel: make(chan struct{}),
		Body:   &readCloserTestImpl{},
	}

	c.Assert(len(DumpHttpRequest(req)) > 0, Equals, true)
}

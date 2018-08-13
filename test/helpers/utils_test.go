package helpers

import (
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type WithTimeoutTest struct{}

var _ = Suite(&WithTimeoutTest{})

func (s *WithTimeoutTest) TestTriggerErrorOnTimeout(c *C) {
	body := func() bool { return false }
	err := WithTimeout(body, "Error on timeout", &TimeoutConfig{
		Timeout: 3,
		Ticker:  1})
	c.Assert(err, NotNil)
}

func (s *WithTimeoutTest) TestTriggerCorrectlyActions(c *C) {
	n := 0
	body := func() bool {
		if n >= 3 {
			return true
		}
		n++
		return false
	}
	err := WithTimeout(body, "Error on timeout", &TimeoutConfig{
		Timeout: 5,
		Ticker:  1})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 3)
}

func (s *WithTimeoutTest) TestBlockingAction(c *C) {
	n := 0
	body := func() bool {
		n++
		time.Sleep(10 * time.Second)
		return false
	}
	err := WithTimeout(body, "Error on timeout", &TimeoutConfig{
		Timeout: 3,
		Ticker:  1})
	c.Assert(err, NotNil)

	c.Assert(n, Equals, 1)

}

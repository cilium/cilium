package types

import (
	. "gopkg.in/check.v1"
)

const (
	CONSUMER_ID1 = 10
	CONSUMER_ID2 = 20
	CONSUMER_ID3 = 30
)

func (s *CommonSuite) TestNewConsumer(c *C) {
	consumer := NewConsumer(CONSUMER_ID1)
	c.Assert(consumer.ID, Equals, CONSUMER_ID1)
	c.Assert(consumer.Decision, Equals, ACCEPT)
}

func (s *CommonSuite) TestGetConsumer(c *C) {
	c1 := GetConsumable(CONSUMER_ID1, nil)
	c.Assert(c1.Iteration, Equals, 0)
	c2 := GetConsumable(CONSUMER_ID1, nil)
	c.Assert(c1, Equals, c2)

	c3 := GetConsumable(CONSUMER_ID2, nil)
	c.Assert(c1, Not(Equals), c3)
}

func (s *CommonSuite) TestConsumer(c *C) {
	var nilConsumer *Consumer

	c1 := GetConsumable(CONSUMER_ID1, nil)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, false)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, false)

	c1.AllowConsumer(CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, true)
	consumer1 := c1.Consumer(CONSUMER_ID2)
	c.Assert(consumer1.ID, Equals, CONSUMER_ID2)

	c1.AllowConsumer(CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, true)
	consumer2 := c1.Consumer(CONSUMER_ID2)
	c.Assert(consumer2.ID, Equals, CONSUMER_ID2)

	c1.AllowConsumer(CONSUMER_ID3)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, true)
	consumer3 := c1.Consumer(CONSUMER_ID3)
	c.Assert(consumer3.ID, Equals, CONSUMER_ID3)

	c1.BanConsumer(CONSUMER_ID2)
	c.Assert(c1.Allows(CONSUMER_ID2), Equals, false)
	consumer2 = c1.Consumer(CONSUMER_ID2)
	c.Assert(consumer2, Equals, nilConsumer)

	c1.BanConsumer(CONSUMER_ID3)
	c.Assert(c1.Allows(CONSUMER_ID3), Equals, false)
	consumer3 = c1.Consumer(CONSUMER_ID3)
	c.Assert(consumer3, Equals, nilConsumer)
}

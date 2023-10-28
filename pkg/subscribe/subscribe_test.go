package subscribe

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSubscription(t *testing.T) {
	subscription := InitSubscription[int]()
	ctx := context.Background()

	sub1 := subscription.Subscribe(ctx)
	sub2 := subscription.Subscribe(ctx)

	subscription.Send(10)

	assert.Equal(t, <-sub1.events, 10)
	assert.Equal(t, <-sub2.events, 10)
}

func TestSubscriptionCtxDone(t *testing.T) {
	subscription := InitSubscription[int]()
	ctx1 := context.Background()
	ctx2 := context.Background()

	sub1 := subscription.Subscribe(ctx1)
	sub2 := subscription.Subscribe(ctx2)

	subscription.Send(10)

	assert.Equal(t, <-sub1.events, 10)
	assert.Equal(t, <-sub2.events, 10)

	ctx1.Done()
	subscription.Send(20)

	select {
	case <-sub1.events:
	default:
		t.Error("Channel is not closed")
	}
	assert.Equal(t, <-sub2.events, 20)
}

func TestSubscriptionComplete(t *testing.T) {
	subscription := InitSubscription[int]()
	ctx1 := context.Background()
	ctx2 := context.Background()

	sub1 := subscription.Subscribe(ctx1)
	sub2 := subscription.Subscribe(ctx2)

	subscription.Send(10)

	assert.Equal(t, <-sub1.events, 10)
	assert.Equal(t, <-sub2.events, 10)

	subscription.Complete()

	// Fixme: Need a better way to close.
	time.Sleep(2 * time.Second)
	select {
	case v := <-sub1.events:
		fmt.Println(v)
	// case v := <-sub2.events:
	// 	fmt.Println(v)
	default:
		t.Error("Channel is not closed")
	}
}

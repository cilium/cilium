package kafka

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"sync"
	"time"

	"github.com/optiopay/kafka/proto"
)

// DistributingProducer is the interface similar to Producer, but never require
// to explicitly specify partition.
//
// Distribute writes messages to the given topic, automatically choosing
// partition, returning the post-commit offset and any error encountered. The
// offset of each message is also updated accordingly.
type DistributingProducer interface {
	Distribute(topic string, messages ...*proto.Message) (offset int64, err error)
}

type randomProducer struct {
	producer   Producer
	partitions int32

	rand saferand
}

// custom math/rand randomizer is not concurrency safe
type saferand struct {
	mu sync.Mutex
	r  *rand.Rand
}

func (sr *saferand) Intn(n int) int {
	sr.mu.Lock()
	res := sr.r.Intn(n)
	sr.mu.Unlock()
	return res
}

// NewRandomProducer wraps given producer and return DistributingProducer that
// publish messages to kafka, randomly picking partition number from range
// [0, numPartitions)
func NewRandomProducer(p Producer, numPartitions int32) DistributingProducer {
	return &randomProducer{
		rand:       saferand{r: rand.New(rand.NewSource(time.Now().UnixNano()))},
		producer:   p,
		partitions: numPartitions,
	}
}

// Distribute write messages to given kafka topic, randomly destination choosing
// partition. All messages written within single Produce call are atomically
// written to the same destination.
func (p *randomProducer) Distribute(topic string, messages ...*proto.Message) (offset int64, err error) {
	// In the case there are no partitions, which may happen for new topics
	// when AllowTopicCreation is passed, we will write to partition 0
	// since rand.Intn panics with 0
	part := 0
	if p.partitions > 0 {
		part = p.rand.Intn(int(p.partitions))
	}
	return p.producer.Produce(topic, int32(part), messages...)
}

type roundRobinProducer struct {
	producer   Producer
	partitions int32
	mu         sync.Mutex
	next       int32
}

// NewRoundRobinProducer wraps given producer and return DistributingProducer
// that publish messages to kafka, choosing destination partition from cycle
// build from [0, numPartitions) range.
func NewRoundRobinProducer(p Producer, numPartitions int32) DistributingProducer {
	return &roundRobinProducer{
		producer:   p,
		partitions: numPartitions,
		next:       0,
	}
}

// Distribute write messages to given kafka topic, choosing next destination
// partition from internal cycle. All messages written within single Produce
// call are atomically written to the same destination.
func (p *roundRobinProducer) Distribute(topic string, messages ...*proto.Message) (offset int64, err error) {
	p.mu.Lock()
	part := p.next
	p.next++
	if p.next >= p.partitions {
		p.next = 0
	}
	p.mu.Unlock()

	return p.producer.Produce(topic, int32(part), messages...)
}

type hashProducer struct {
	producer   Producer
	partitions int32
}

// NewHashProducer wraps given producer and return DistributingProducer that
// publish messages to kafka, computing partition number from message key hash,
// using fnv hash and [0, numPartitions) range.
func NewHashProducer(p Producer, numPartitions int32) DistributingProducer {
	return &hashProducer{
		producer:   p,
		partitions: numPartitions,
	}
}

// Distribute write messages to given kafka topic, computing partition number from
// the message key value. Message key must be not nil and all messages written
// within single Produce call are atomically written to the same destination.
//
// All messages passed within single Produce call must hash to the same
// destination, otherwise no message is written and error is returned.
func (p *hashProducer) Distribute(topic string, messages ...*proto.Message) (offset int64, err error) {
	if len(messages) == 0 {
		return 0, errors.New("no messages")
	}
	part, err := messageHashPartition(messages[0].Key, p.partitions)
	if err != nil {
		return 0, fmt.Errorf("cannot hash message: %s", err)
	}
	// make sure that all messages within single call are to the same destination
	for i := 2; i < len(messages); i++ {
		mp, err := messageHashPartition(messages[i].Key, p.partitions)
		if err != nil {
			return 0, fmt.Errorf("cannot hash message: %s", err)
		}
		if part != mp {
			return 0, errors.New("cannot publish messages to different destinations")
		}
	}

	return p.producer.Produce(topic, part, messages...)
}

// messageHashPartition compute destination partition number for given key
// value and total number of partitions.
func messageHashPartition(key []byte, partitions int32) (int32, error) {
	if key == nil {
		return 0, errors.New("no key")
	}
	hasher := fnv.New32a()
	if _, err := hasher.Write(key); err != nil {
		return 0, fmt.Errorf("cannot hash key: %s", err)
	}
	sum := int32(hasher.Sum32())
	if sum < 0 {
		sum = -sum
	}
	return sum % partitions, nil
}

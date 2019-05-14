// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package proxy

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/logger"

	"github.com/optiopay/kafka"
	"github.com/optiopay/kafka/proto"
	"github.com/sirupsen/logrus"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type proxyTestSuite struct {
	repo *policy.Repository
}

var _ = Suite(&proxyTestSuite{})

func (s *proxyTestSuite) SetUpSuite(c *C) {
	s.repo = policy.NewPolicyRepository()
}

type DummySelectorCacheUser struct{}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector policy.CachedSelector, selections, added, deleted []identity.NumericIdentity) {
}

var (
	localEndpointMock logger.EndpointUpdater = &proxyUpdaterMock{
		id:       1000,
		ipv4:     "10.0.0.1",
		ipv6:     "f00d::1",
		labels:   []string{"id.foo", "id.bar"},
		identity: identity.NumericIdentity(256),
	}

	dummySelectorCacheUser = &DummySelectorCacheUser{}
	testSelectorCache      = policy.NewSelectorCache(cache.IdentityCache{})

	wildcardCachedSelector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, api.WildcardEndpointSelector)
)

// newTestBrokerConf returns BrokerConf with default configuration adjusted for
// tests
func newTestBrokerConf(clientID string) kafka.BrokerConf {
	conf := kafka.NewBrokerConf(clientID)
	conf.DialTimeout = 400 * time.Millisecond
	conf.LeaderRetryLimit = 10
	conf.LeaderRetryWait = 2 * time.Millisecond
	return conf
}

type loggerMap struct{}

func fields(args ...interface{}) logrus.Fields {
	fields := logrus.Fields{}
	for i := 0; i+1 < len(args); i += 2 {
		fields[args[i].(string)] = args[i+1]
	}
	return fields
}

func (loggerMap) Debug(msg string, args ...interface{}) { log.WithFields(fields(args...)).Debug(msg) }
func (loggerMap) Info(msg string, args ...interface{})  { log.WithFields(fields(args...)).Info(msg) }
func (loggerMap) Warn(msg string, args ...interface{})  { log.WithFields(fields(args...)).Warn(msg) }
func (loggerMap) Error(msg string, args ...interface{}) { log.WithFields(fields(args...)).Error(msg) }

var (
	proxyAddress = "127.0.0.1"
)

type metadataTester struct {
	host               string
	port               uint16
	topics             map[string]bool
	allowCreate        bool
	numGeneralFetches  int
	numSpecificFetches int
}

func newMetadataHandler(srv *Server, allowCreate bool, proxyPort uint16) *metadataTester {
	tester := &metadataTester{
		host:        proxyAddress,
		port:        proxyPort,
		allowCreate: allowCreate,
		topics:      make(map[string]bool),
	}
	tester.topics["allowedTopic"] = true
	tester.topics["disallowedTopic"] = true
	return tester
}

func (m *metadataTester) NumGeneralFetches() int {
	return m.numGeneralFetches
}

func (m *metadataTester) NumSpecificFetches() int {
	return m.numSpecificFetches
}

func (m *metadataTester) Handler() RequestHandler {
	return func(request Serializable) Serializable {
		req := request.(*proto.MetadataReq)

		if len(req.Topics) == 0 {
			m.numGeneralFetches++
		} else {
			m.numSpecificFetches++
		}

		resp := &proto.MetadataResp{
			CorrelationID: req.CorrelationID,
			Brokers: []proto.MetadataRespBroker{
				{NodeID: 1, Host: m.host, Port: int32(m.port)},
			},
			Topics: []proto.MetadataRespTopic{},
		}

		wantsTopic := make(map[string]bool)
		for _, topic := range req.Topics {
			if m.allowCreate {
				m.topics[topic] = true
			}
			wantsTopic[topic] = true
		}

		for topic := range m.topics {
			// Return either all topics or only topics that they explicitly requested
			_, explicitTopic := wantsTopic[topic]
			if len(req.Topics) > 0 && !explicitTopic {
				continue
			}

			resp.Topics = append(resp.Topics, proto.MetadataRespTopic{
				Name: topic,
				Partitions: []proto.MetadataRespPartition{
					{
						ID:       0,
						Leader:   1,
						Replicas: []int32{1},
						Isrs:     []int32{1},
					},
					{
						ID:       1,
						Leader:   1,
						Replicas: []int32{1},
						Isrs:     []int32{1},
					},
				},
			})
		}
		return resp
	}
}

func (s *proxyTestSuite) TestKafkaRedirect(c *C) {
	server := NewServer()
	server.Start()
	defer server.Close()

	log.WithFields(logrus.Fields{
		"address": server.Address(),
	}).Debug("Started kafka server")

	pp := getProxyPort(policy.ParserTypeKafka, true)
	c.Assert(pp.configured, Equals, false)
	var err error
	pp.proxyPort, err = allocatePort(pp.proxyPort, 10000, 20000)
	c.Assert(err, IsNil)
	c.Assert(pp.proxyPort, Not(Equals), 0)
	pp.reservePort()
	c.Assert(pp.configured, Equals, true)

	proxyAddress := fmt.Sprintf("%s:%d", proxyAddress, uint16(pp.proxyPort))

	kafkaRule1 := api.PortRuleKafka{APIKey: "metadata", APIVersion: "0"}
	c.Assert(kafkaRule1.Sanitize(), IsNil)

	kafkaRule2 := api.PortRuleKafka{APIKey: "produce", APIVersion: "0", Topic: "allowedTopic"}
	c.Assert(kafkaRule2.Sanitize(), IsNil)

	// Insert a mock EP to the endpointmanager so that DefaultEndpointInfoRegistry may find
	// the EP ID by the IP.
	ep := endpoint.NewEndpointWithState(s.repo, uint16(localEndpointMock.GetID()), endpoint.StateReady)
	ipv4, err := addressing.NewCiliumIPv4("127.0.0.1")
	c.Assert(err, IsNil)
	ep.IPv4 = ipv4
	ep.UpdateLogger(nil)
	endpointmanager.Insert(ep)
	defer endpointmanager.Remove(ep)

	_, dstPortStr, err := net.SplitHostPort(server.Address())
	c.Assert(err, IsNil)
	portInt, err := strconv.Atoi(dstPortStr)
	c.Assert(err, IsNil)
	r := newRedirect(localEndpointMock, pp, uint16(portInt))

	r.rules = policy.L7DataMap{
		wildcardCachedSelector: api.L7Rules{
			Kafka: []api.PortRuleKafka{kafkaRule1, kafkaRule2},
		},
	}

	redir, err := createKafkaRedirect(r, kafkaConfiguration{
		lookupSrcID: func(mapname, remoteAddr, localAddr string, ingress bool) (uint32, error) {
			return uint32(1000), nil
		},
		// Disable use of SO_MARK, IP_TRANSPARENT for tests
		testMode: true,
	}, DefaultEndpointInfoRegistry)
	c.Assert(err, IsNil)
	defer redir.Close(nil)

	log.WithFields(logrus.Fields{
		"address": proxyAddress,
	}).Debug("Started kafka proxy")

	server.Handle(MetadataRequest, newMetadataHandler(server, false, r.listener.proxyPort).Handler())

	broker, err := kafka.Dial([]string{proxyAddress}, newTestBrokerConf("tester"))
	if err != nil {
		c.Fatalf("cannot create broker: %s", err)
	}

	// setup producer
	prodConf := kafka.NewProducerConf()
	prodConf.RetryWait = time.Millisecond
	prodConf.Logger = loggerMap{}
	producer := broker.Producer(prodConf)
	messages := []*proto.Message{
		{Value: []byte("first")},
		{Value: []byte("second")},
	}

	// Start handling allowedTopic produce requests
	server.Handle(ProduceRequest, func(request Serializable) Serializable {
		req := request.(*proto.ProduceReq)
		log.WithField(logfields.Request, logfields.Repr(req)).Debug("Handling req")
		return &proto.ProduceResp{
			CorrelationID: req.CorrelationID,
			Topics: []proto.ProduceRespTopic{
				{
					Name: req.Topics[0].Name,
					Partitions: []proto.ProduceRespPartition{
						{
							ID:     0,
							Offset: 5,
						},
					},
				},
			},
		}
	})

	// send a Produce request for an allowed topic
	offset, err := producer.Produce("allowedTopic", 0, messages...)
	c.Assert(err, IsNil)
	c.Assert(offset, Equals, int64(5))

	// send a Produce request for disallowed topic
	_, err = producer.Produce("disallowedTopic", 0, messages...)
	c.Assert(err, Equals, proto.ErrTopicAuthorizationFailed)

	log.Debug("Testing done, closing listen socket")
	finalize, _ := redir.Close(nil)
	finalize()

	// In order to see in the logs that the connections get closed after the
	// 1-minute timeout, uncomment this line:
	// time.Sleep(2 * time.Minute)
}

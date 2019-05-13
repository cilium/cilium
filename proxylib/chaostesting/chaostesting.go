// Copyright 2018 Authors of Cilium
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

package chaostesting

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/cilium/cilium/proxylib/proxylib"

	"github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

// ChaosRule is a single rule inducing chaos. The user can specify multiple
// rules via the CiliumNetworkPolicy custom resource.
type ChaosRule struct {
	method             string
	statusCode         int
	probability        float64
	probabilitySource  *rand.Rand
	delayRequest       time.Duration
	delayResponse      time.Duration
	rewriteStatus      string
	addRequestHeaders  map[string]string
	addResponseHeaders map[string]string
	pathRegexp         *regexp.Regexp
}

func (c *ChaosRule) matchRequest(req *http.Request) bool {
	log.Debugf("Matches() called on HTTP request, rule: %#v", c)

	if c.probability != float64(0) {
		if c.probabilitySource.Float64() > c.probability {
			return false
		}
	}

	if c.method != "" && c.method != req.Method {
		return false
	}

	if c.pathRegexp != nil && req.URL != nil {
		if !c.pathRegexp.MatchString(req.URL.EscapedPath()) {
			return false
		}
	}

	for k, v := range c.addRequestHeaders {
		req.Header.Add(k, v)
	}

	if c.delayRequest != time.Duration(0) {
		log.Debugf("Delaying request for %v", c.delayRequest)
		time.Sleep(c.delayRequest)
		req.Header.Add("X-Cilium-Delay", fmt.Sprintf("Delayed request by %s", c.delayRequest))
	}

	return true
}

func (c *ChaosRule) matchResponse(resp *http.Response) bool {
	log.Debugf("Matches() called on HTTP response, rule: %#v", c)

	if c.probability != float64(0) {
		if c.probabilitySource.Float64() > c.probability {
			return false
		}
	}

	if c.statusCode != 0 && c.statusCode != resp.StatusCode {
		return false
	}

	if c.delayResponse != time.Duration(0) {
		log.Debugf("Delaying response for %v", c.delayRequest)
		time.Sleep(c.delayResponse)
		resp.Header.Add("X-Cilium-Delay", fmt.Sprintf("Delayed response by %s", c.delayRequest))
	}

	for k, v := range c.addResponseHeaders {
		resp.Header.Add(k, v)
	}

	if c.rewriteStatus != "" {
		resp.Status = c.rewriteStatus
		chunks := strings.SplitN(c.rewriteStatus, " ", 2)
		if len(chunks) == 2 {
			i, err := strconv.ParseInt(chunks[0], 10, 64)
			if err == nil {
				resp.StatusCode = int(i)
			}
		}
		resp.Header.Add("X-Cilium-Modified-Status-Code", "The status code has been modified by Cilium")
	}

	return true
}

// Matches is called when the HTTP request or response has been fully parsed.
// It evaluates the filters of the rule and applies the actions if the filter
// matches. true is returned if the filter matched.
func (c *ChaosRule) Matches(obj interface{}) bool {

	switch obj.(type) {
	case *http.Request:
		req := obj.(*http.Request)
		return c.matchRequest(req)

	case *http.Response:
		resp := obj.(*http.Response)
		return c.matchResponse(resp)

	default:
		log.Warningf("Invalid object passed into Matches(): %#v", obj)
		return false
	}
}

func parseKeyValueList(val string) (result map[string]string) {
	result = map[string]string{}
	for _, header := range strings.Split(val, ",") {
		kv := strings.SplitN(header, "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		} else {
			result[kv[0]] = ""
		}
	}
	return
}

// CHaosTestingRuleParser parses a PortNetworkPolicyRule as provided by the
// user via a custom resource and parses the chaos testing specific elements in
// it. On error the function must call ParseError() to indicate the parsing
// problem.
func ChaosTestingRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	var rules []L7NetworkPolicyRule

	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var cr ChaosRule

		for k, v := range l7Rule.Rule {
			switch k {
			case "method":
				cr.method = v

			case "path":
				r, err := regexp.Compile(v)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse regular exprresion for method '%s': %s", v, err), rule)
				} else {
					cr.pathRegexp = r
				}

			case "probability":
				f, err := strconv.ParseFloat(v, 64)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse probability %s: %s", v, err), rule)
				} else {
					cr.probabilitySource = rand.New(rand.NewSource(time.Now().UnixNano()))
					cr.probability = f
				}

			case "status-code":
				i, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse status-code %s: %s", v, err), rule)
				} else {
					cr.statusCode = int(i)
				}

			case "delay-request":
				delay, err := time.ParseDuration(v)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse delay-request duration %s: %s", v, err), rule)
				} else {
					log.Debugf("Setting delay to %v", delay)
					cr.delayRequest = delay
				}

			case "delay-response":
				delay, err := time.ParseDuration(v)
				if err != nil {
					ParseError(fmt.Sprintf("unable to parse delay-response duration %s: %s", v, err), rule)
				} else {
					log.Debugf("Setting delay to %v", delay)
					cr.delayResponse = delay
				}

			case "rewrite-status":
				cr.rewriteStatus = v

			case "add-request-headers":
				if cr.addRequestHeaders == nil {
					cr.addRequestHeaders = map[string]string{}
				}
				for k, v := range parseKeyValueList(v) {
					cr.addRequestHeaders[k] = v
				}

			case "add-response-headers":
				if cr.addResponseHeaders == nil {
					cr.addResponseHeaders = map[string]string{}
				}
				for k, v := range parseKeyValueList(v) {
					cr.addResponseHeaders[k] = v
				}

			default:
				ParseError(fmt.Sprintf("Unsupported rule key : %s", k), rule)
			}
		}

		log.Debugf("Parsed ChaosTestingRule : %v", cr)
		rules = append(rules, &cr)
	}
	return rules
}

// ChaosTestingFactory is response to create ChaosTestingParser objects for new
// connections
type ChaosTestingFactory struct{}

var chaosTestingFactory *ChaosTestingFactory

func init() {
	log.Info("init(): Registering chaos-testing Envoy plugin")
	RegisterParserFactory("chaos", chaosTestingFactory)
	RegisterL7RuleParser("chaos", ChaosTestingRuleParser)
}

type envoyDataReader struct {
	name string
	pipe *directionalReader
	data [][]byte
	skip int
	eof  bool
}

func newEnvoyDataReader(name string, pipe *directionalReader) *envoyDataReader {
	e := &envoyDataReader{
		name: name,
		pipe: pipe,
	}

	return e
}

func (e *envoyDataReader) Read(p []byte) (int, error) {
	log.Debugf("%s: attempting to read  %d bytes, have %d slides", e.name, len(p), len(e.data))

	skip := e.skip
OUTER:
	for _, slice := range e.data {
		for skip > 0 {
			log.Debugf("%d left to skip", skip)
			if e.skip >= len(slice) {
				log.Debugf("%s: read - skipping %d bytes", e.name, len(slice))
				skip -= len(slice)
				continue OUTER
			}

			log.Debugf("%s: read - skipping %d bytes", e.name, skip)
			slice = slice[skip:]
			skip = 0
		}

		if len(p) < len(slice) {
			slice = slice[:len(p)]
		}

		log.Debugf("%s: returning %d bytes", e.name, len(slice))
		e.skip += len(slice)
		e.eof = false
		copy(p, slice)
		log.Debugf("Returning %s", string(slice))
		return len(slice), nil
	}

	log.Debugf("returning EOF")
	e.eof = true
	return 0, io.EOF
}

type directionalReader struct {
	name             string
	envoyReader      *envoyDataReader
	bufferedReader   *bufio.Reader
	injectionStarted bool
	injectBuffer     []byte
	reply            bool

	bytesReady int
}

func newDirectionalReader(name string, reply bool) *directionalReader {
	p := &directionalReader{
		name:  name,
		reply: reply,
	}
	p.envoyReader = newEnvoyDataReader(name, p)
	p.bufferedReader = bufio.NewReader(p.envoyReader)
	return p
}

func (p *directionalReader) inject(connection *Connection, reply bool) int {
	log.Debugf("Attempting to inject %d bytes", len(p.injectBuffer))
	n := connection.Inject(reply, p.injectBuffer)
	log.Debugf("%s: Injected %d bytes, %d remaining", p.name, n, len(p.injectBuffer)-n)
	if n > 0 && len(p.injectBuffer) != n {
		p.injectBuffer = p.injectBuffer[n:]
		log.Debugf("Setting inject buffer to new length %d", len(p.injectBuffer))
	} else {
		log.Debugf("Resetting inject buffer")
		p.injectBuffer = nil
	}
	return n
}

func (p *directionalReader) injectLeftovers(connection *Connection, reply bool) int {
	if len(p.injectBuffer) > 0 {
		injected := p.inject(connection, reply)
		if injected > 0 {
			return injected
		}
	}

	if p.injectBuffer != nil {
		log.Debugf("Resetting inject buffer 2x")
		p.injectBuffer = nil
	}

	return 0
}

// ChaosTestingParser is an Envoy go extension to induce chaos in
// HTTP/REST-based communication between services
type ChaosTestingParser struct {
	connection     *Connection
	reqReader      *directionalReader
	respReader     *directionalReader
	lastRequest    *http.Request
	requestMatched bool
}

// Create is called by Envoy when a new connection has been created and a parser must be instantiated
func (f *ChaosTestingFactory) Create(connection *Connection) Parser {
	log.Debugf("ChaosTestingParser Create: %v", connection)

	return &ChaosTestingParser{
		connection: connection,
		reqReader:  newDirectionalReader("request", false),
		respReader: newDirectionalReader("response", true),
	}
}

func (p *ChaosTestingParser) readRequest() (*http.Request, error) {
	p.reqReader.envoyReader.skip = 0

	log.Debugf("Starting to read new HTTP request")
	req, err := http.ReadRequest(p.reqReader.bufferedReader)
	if p.reqReader.envoyReader.eof {
		return nil, nil
	}
	if err != nil {
		log.Debugf("Got error...: %s", err)
		return nil, err
	}

	b := new(bytes.Buffer)
	io.Copy(b, req.Body)
	req.Body.Close()
	req.Body = ioutil.NopCloser(b)

	if p.reqReader.envoyReader.eof {
		log.Debugf("EOF while reading body")
		return nil, nil
	}

	p.connection.Log(cilium.EntryType_Request,
		&cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "http",
				Fields: map[string]string{
					"method": req.Method,
					"url":    req.URL.EscapedPath(),
					"length": fmt.Sprintf("%d", req.ContentLength),
				},
			},
		})

	log.Debugf("Read HTTP request: %#v", req)
	return req, nil
}

func (p *ChaosTestingParser) readResponse(req *http.Request) (*http.Response, error) {
	p.respReader.envoyReader.skip = 0

	log.Debugf("Starting to read new HTTP response")
	resp, err := http.ReadResponse(p.respReader.bufferedReader, req)
	if p.respReader.envoyReader.eof {
		return nil, nil
	}
	if err != nil {
		log.Debugf("Error parsing read response: %s", err)
		return nil, err
	}

	b := new(bytes.Buffer)
	io.Copy(b, resp.Body)
	resp.Body.Close()
	resp.Body = ioutil.NopCloser(b)

	if p.respReader.envoyReader.eof {
		log.Debugf("EOF while reading body")
		return nil, nil
	}

	p.connection.Log(cilium.EntryType_Response,
		&cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "http",
				Fields: map[string]string{
					"status": resp.Status,
					"length": fmt.Sprintf("%d", resp.ContentLength),
				},
			},
		})

	log.Debugf("Read HTTP response: %#v", resp)
	return resp, nil
}

func equalBuffer(buf *bytes.Buffer, data [][]byte) bool {
	var (
		b      = buf.Bytes()
		offset = 0
	)

	for _, d := range data {
		if len(d)+offset > len(b) {
			return false
		}

		if !bytes.Equal(b[offset:offset+len(d)], d) {
			return false
		}

		offset += len(d)
	}

	return true
}

// OnData is called by Envoy whenever there is new data to parse in either the
// request or response direction
func (p *ChaosTestingParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {
	log.Debugf("OnData: reply=%t endStream=%t %d slices", reply, endStream, len(dataArray))

	if reply {
		if injected := p.respReader.injectLeftovers(p.connection, true); injected > 0 {
			log.Debugf("Returning INJECT")
			return INJECT, injected
		}

		p.respReader.envoyReader.data = dataArray

		resp, err := p.readResponse(p.lastRequest)
		if err != nil {
			log.Debugf("Returning ERROR")
			return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
		}
		if resp == nil {
			log.Debugf("Returning MORE")
			return MORE, 1
		}

		if !p.respReader.injectionStarted {
			p.respReader.injectionStarted = true
			log.Debugf("parsed response %#v", resp)

			// No point in executing the rule on the response if
			// the request did not match
			if p.requestMatched {
				p.connection.Matches(resp)
			}

			buf := new(bytes.Buffer)
			resp.Write(buf)

			if !p.requestMatched || equalBuffer(buf, dataArray) {
				log.Debugf("Returning PASS")
				p.respReader.injectionStarted = false
				return PASS, len(buf.Bytes())
			}

			p.respReader.injectBuffer = buf.Bytes()
			injected := p.respReader.inject(p.connection, true)
			log.Debugf("Returning INJECT")
			return INJECT, injected
		}

		p.respReader.injectionStarted = false
		return NOP, 0
	}

	if injected := p.reqReader.injectLeftovers(p.connection, false); injected > 0 {
		log.Debugf("Returning INJECT")
		return INJECT, injected
	}

	p.reqReader.envoyReader.data = dataArray

	req, err := p.readRequest()
	if err != nil {
		log.Debugf("Returning ERROR")
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}
	if req == nil {
		log.Debugf("Returning MORE")
		return MORE, 1
	}

	if !p.reqReader.injectionStarted {
		p.lastRequest = req
		p.reqReader.injectionStarted = true
		log.Debugf("parsed request %#v", req)

		p.requestMatched = p.connection.Matches(req)
		buf := new(bytes.Buffer)
		req.Write(buf)

		if equalBuffer(buf, dataArray) {
			log.Debugf("Returning PASS")
			p.reqReader.injectionStarted = false
			return PASS, len(buf.Bytes())
		}

		p.reqReader.injectBuffer = buf.Bytes()
		injected := p.reqReader.inject(p.connection, false)
		log.Debugf("Returning INJECT")
		return INJECT, injected
	}

	p.reqReader.injectionStarted = false
	return NOP, 0
}

// Copyright 2016-2017 Authors of Cilium
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

package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/policy"

	"github.com/braintree/manners"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/route"
)

var (
	log     = logging.MustGetLogger("cilium-proxy")
	logFile *os.File
	logBuf  *bufio.Writer
)

type Redirect struct {
	id       string
	FromPort uint16
	ToPort   uint16
	Rules    []policy.AuxRule
	source   ProxySource
	server   *manners.GracefulServer
	router   route.Router
}

func (r *Redirect) updateRules(rules []policy.AuxRule) {
	for _, v := range r.Rules {
		r.router.RemoveRoute(v.Expr)
	}

	r.Rules = make([]policy.AuxRule, len(rules))
	copy(r.Rules, rules)

	for _, v := range r.Rules {
		r.router.AddRoute(v.Expr, v)
	}
}

type ProxySource interface {
}

type Proxy struct {
	// mutex is the lock required when modifying any proxy datastructure
	mutex sync.RWMutex

	// rangeMin is the minimum port used for proxy port allocation
	rangeMin uint16

	// rangeMax is the maximum port used for proxy port allocation.
	// If port is unspecified, the proxy will automatically allocate
	// ports out of the rangeMin-rangeMax range.
	rangeMax uint16

	// nextPort is the next available proxy port to use
	nextPort uint16

	// allocatedPorts is a map of all allocated proxy ports pointing
	// to the redirect rules attached to that port
	allocatedPorts map[uint16]*Redirect

	// redirects is a map of all redirect configurations indexed by
	// the redirect identifier
	redirects map[string]*Redirect
}

func NewProxy(minPort uint16, maxPort uint16) *Proxy {
	return &Proxy{
		rangeMin:       minPort,
		rangeMax:       maxPort,
		nextPort:       minPort,
		redirects:      make(map[string]*Redirect),
		allocatedPorts: make(map[uint16]*Redirect),
	}
}

func (p *Proxy) allocatePort() (uint16, error) {
	port := p.nextPort

	for {
		resPort := port
		port++
		if port >= p.rangeMax {
			port = p.rangeMin
		}

		if _, ok := p.allocatedPorts[resPort]; !ok {
			return resPort, nil
		}

		if port == p.nextPort {
			return 0, fmt.Errorf("no available proxy ports")
		}
	}
}

func generateURL(w http.ResponseWriter, req *http.Request, dport uint16) (*url.URL, error) {
	ip, port, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid remote address: %s", err)
	}

	pIP := net.ParseIP(ip)
	if pIP == nil {
		return nil, fmt.Errorf("unable to parse IP %s", ip)
	}

	sport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("unable to parse port string: %s", err)
	}

	key := &Proxy4Key{
		SPort:   uint16(sport),
		DPort:   dport,
		Nexthdr: 6,
	}

	copy(key.SAddr[:], pIP.To4())

	val, err := LookupEgress4(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to find proxy entry for %s: %s", key, err)
	}

	newUrl := *req.URL
	newUrl.Scheme = "http"
	newUrl.Host = val.HostPort()
	log.Debugf("Found proxy entry: %+v, new-url %+v\n", val, newUrl)

	return &newUrl, nil
}

var gcOnce sync.Once

type LogRecord struct {
	timeStart time.Time
	timeDiff  time.Duration
	code      int
	req       *http.Request
}

func (r *Redirect) Log(l *LogRecord, code int, reason string) {
	if logBuf == nil {
		return
	}

	ip, _, err := net.SplitHostPort(l.req.RemoteAddr)
	if err != nil {
		return
	}

	fmt.Fprintf(logBuf, "%s - - [%s] \"%s %s %s %d %d\" %f\n",
		ip,
		l.timeStart.Format("02/Jan/2006 03:04:05"),
		l.req.Method, l.req.RequestURI, l.req.Proto,
		code, 0, l.timeDiff.Seconds())
	logBuf.Flush()
}

func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, source ProxySource) (*Redirect, error) {
	fwd, err := forward.New()
	if err != nil {
		return nil, err
	}

	if strings.ToLower(l4.L7Parser) != "http" {
		return nil, fmt.Errorf("unknown L7 protocol \"%s\"", l4.L7Parser)
	}

	for _, r := range l4.L7Rules {
		if !route.IsValid(r.Expr) {
			return nil, fmt.Errorf("invalid filter expression: %s", r.Expr)
		}
	}

	gcOnce.Do(func() {
		if lf := viper.GetString("access-log"); lf != "" {
			if logFile, err = os.OpenFile(lf, os.O_APPEND|os.O_WRONLY, 0666); err != nil {
				log.Warningf("cannot open access log: %s", err)
			} else {
				logBuf = bufio.NewWriter(logFile)
			}
		}

		go func() {
			for {
				time.Sleep(time.Duration(10) * time.Second)
				if deleted := GC(); deleted > 0 {
					log.Debugf("Evicted %d entries from proxy table\n", deleted)
				}
			}
		}()
	})

	p.mutex.Lock()

	if r, ok := p.redirects[id]; ok {
		r.updateRules(l4.L7Rules)
		log.Debugf("updated existing proxy instance %+v", r)
		p.mutex.Unlock()
		return r, nil
	}

	to, err := p.allocatePort()
	if err != nil {
		p.mutex.Unlock()
		return nil, err
	}

	redir := &Redirect{
		id:       id,
		FromPort: uint16(l4.Port),
		ToPort:   to,
		source:   source,
		router:   route.New(),
	}

	redirect := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		startDelta := time.Now()
		record := &LogRecord{
			req:       req,
			timeStart: time.Time{},
		}

		reason := "no rules"

		// Validate access to L4/L7 resource
		p.mutex.Lock()
		if len(redir.Rules) > 0 {
			rule, _ := redir.router.Route(req)
			if rule == nil {
				http.Error(w, "Access denied", http.StatusForbidden)
				p.mutex.Unlock()
				redir.Log(record, http.StatusForbidden, "access denied")
				return
			} else {
				ar := rule.(policy.AuxRule)
				log.Debugf("Allowing request based on rule %+v\n", ar)
				reason = fmt.Sprintf("rule: %+v", ar)
			}
		}
		p.mutex.Unlock()

		// Reconstruct original URL used for the request
		if newURL, err := generateURL(w, req, to); err != nil {
			log.Errorf("%s\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			redir.Log(record, http.StatusBadRequest, fmt.Sprintf("cannot generate url: %s", err))
			return
		} else {
			req.URL = newURL
		}

		fwd.ServeHTTP(w, req)
		record.timeDiff = time.Now().UTC().Sub(startDelta)
		redir.Log(record, http.StatusOK, reason)
	})

	redir.server = manners.NewWithServer(&http.Server{
		Addr:    fmt.Sprintf(":%d", to),
		Handler: redirect,
	})

	redir.updateRules(l4.L7Rules)
	p.allocatedPorts[to] = redir
	p.redirects[id] = redir

	p.mutex.Unlock()

	log.Debugf("Created new proxy intance %+v", redir)

	go redir.server.ListenAndServe()

	return redir, nil
}

func (p *Proxy) RemoveRedirect(id string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if r, ok := p.redirects[id]; !ok {
		return fmt.Errorf("unable to find redirect %s", id)
	} else {
		r.server.Close()

		delete(p.redirects, r.id)
		delete(p.allocatedPorts, r.ToPort)
	}

	return nil
}

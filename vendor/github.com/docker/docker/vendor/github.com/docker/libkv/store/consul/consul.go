package consul

import (
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	api "github.com/hashicorp/consul/api"
)

const (
	// DefaultWatchWaitTime is how long we block for at a
	// time to check if the watched key has changed. This
	// affects the minimum time it takes to cancel a watch.
	DefaultWatchWaitTime = 15 * time.Second

	// RenewSessionRetryMax is the number of time we should try
	// to renew the session before giving up and throwing an error
	RenewSessionRetryMax = 5

	// MaxSessionDestroyAttempts is the maximum times we will try
	// to explicitely destroy the session attached to a lock after
	// the connectivity to the store has been lost
	MaxSessionDestroyAttempts = 5

	// defaultLockTTL is the default ttl for the consul lock
	defaultLockTTL = 20 * time.Second
)

var (
	// ErrMultipleEndpointsUnsupported is thrown when there are
	// multiple endpoints specified for Consul
	ErrMultipleEndpointsUnsupported = errors.New("consul does not support multiple endpoints")

	// ErrSessionRenew is thrown when the session can't be
	// renewed because the Consul version does not support sessions
	ErrSessionRenew = errors.New("cannot set or renew session for ttl, unable to operate on sessions")
)

// Consul is the receiver type for the
// Store interface
type Consul struct {
	sync.Mutex
	config *api.Config
	client *api.Client
}

type consulLock struct {
	lock    *api.Lock
	renewCh chan struct{}
}

// Register registers consul to libkv
func Register() {
	libkv.AddStore(store.CONSUL, New)
}

// New creates a new Consul client given a list
// of endpoints and optional tls config
func New(endpoints []string, options *store.Config) (store.Store, error) {
	if len(endpoints) > 1 {
		return nil, ErrMultipleEndpointsUnsupported
	}

	s := &Consul{}

	// Create Consul client
	config := api.DefaultConfig()
	s.config = config
	config.HttpClient = http.DefaultClient
	config.Address = endpoints[0]
	config.Scheme = "http"

	// Set options
	if options != nil {
		if options.TLS != nil {
			s.setTLS(options.TLS)
		}
		if options.ConnectionTimeout != 0 {
			s.setTimeout(options.ConnectionTimeout)
		}
	}

	// Creates a new client
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	s.client = client

	return s, nil
}

// SetTLS sets Consul TLS options
func (s *Consul) setTLS(tls *tls.Config) {
	s.config.HttpClient.Transport = &http.Transport{
		TLSClientConfig: tls,
	}
	s.config.Scheme = "https"
}

// SetTimeout sets the timeout for connecting to Consul
func (s *Consul) setTimeout(time time.Duration) {
	s.config.WaitTime = time
}

// Normalize the key for usage in Consul
func (s *Consul) normalize(key string) string {
	key = store.Normalize(key)
	return strings.TrimPrefix(key, "/")
}

func (s *Consul) renewSession(pair *api.KVPair, ttl time.Duration) error {
	// Check if there is any previous session with an active TTL
	session, err := s.getActiveSession(pair.Key)
	if err != nil {
		return err
	}

	if session == "" {
		entry := &api.SessionEntry{
			Behavior:  api.SessionBehaviorDelete, // Delete the key when the session expires
			TTL:       (ttl / 2).String(),        // Consul multiplies the TTL by 2x
			LockDelay: 1 * time.Millisecond,      // Virtually disable lock delay
		}

		// Create the key session
		session, _, err = s.client.Session().Create(entry, nil)
		if err != nil {
			return err
		}

		lockOpts := &api.LockOptions{
			Key:     pair.Key,
			Session: session,
		}

		// Lock and ignore if lock is held
		// It's just a placeholder for the
		// ephemeral behavior
		lock, _ := s.client.LockOpts(lockOpts)
		if lock != nil {
			lock.Lock(nil)
		}
	}

	_, _, err = s.client.Session().Renew(session, nil)
	return err
}

// getActiveSession checks if the key already has
// a session attached
func (s *Consul) getActiveSession(key string) (string, error) {
	pair, _, err := s.client.KV().Get(key, nil)
	if err != nil {
		return "", err
	}
	if pair != nil && pair.Session != "" {
		return pair.Session, nil
	}
	return "", nil
}

// Get the value at "key", returns the last modified index
// to use in conjunction to CAS calls
func (s *Consul) Get(key string) (*store.KVPair, error) {
	options := &api.QueryOptions{
		AllowStale:        false,
		RequireConsistent: true,
	}

	pair, meta, err := s.client.KV().Get(s.normalize(key), options)
	if err != nil {
		return nil, err
	}

	// If pair is nil then the key does not exist
	if pair == nil {
		return nil, store.ErrKeyNotFound
	}

	return &store.KVPair{Key: pair.Key, Value: pair.Value, LastIndex: meta.LastIndex}, nil
}

// Put a value at "key"
func (s *Consul) Put(key string, value []byte, opts *store.WriteOptions) error {
	key = s.normalize(key)

	p := &api.KVPair{
		Key:   key,
		Value: value,
		Flags: api.LockFlagValue,
	}

	if opts != nil && opts.TTL > 0 {
		// Create or renew a session holding a TTL. Operations on sessions
		// are not deterministic: creating or renewing a session can fail
		for retry := 1; retry <= RenewSessionRetryMax; retry++ {
			err := s.renewSession(p, opts.TTL)
			if err == nil {
				break
			}
			if retry == RenewSessionRetryMax {
				return ErrSessionRenew
			}
		}
	}

	_, err := s.client.KV().Put(p, nil)
	return err
}

// Delete a value at "key"
func (s *Consul) Delete(key string) error {
	if _, err := s.Get(key); err != nil {
		return err
	}
	_, err := s.client.KV().Delete(s.normalize(key), nil)
	return err
}

// Exists checks that the key exists inside the store
func (s *Consul) Exists(key string) (bool, error) {
	_, err := s.Get(key)
	if err != nil {
		if err == store.ErrKeyNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// List child nodes of a given directory
func (s *Consul) List(directory string) ([]*store.KVPair, error) {
	pairs, _, err := s.client.KV().List(s.normalize(directory), nil)
	if err != nil {
		return nil, err
	}
	if len(pairs) == 0 {
		return nil, store.ErrKeyNotFound
	}

	kv := []*store.KVPair{}

	for _, pair := range pairs {
		if pair.Key == directory {
			continue
		}
		kv = append(kv, &store.KVPair{
			Key:       pair.Key,
			Value:     pair.Value,
			LastIndex: pair.ModifyIndex,
		})
	}

	return kv, nil
}

// DeleteTree deletes a range of keys under a given directory
func (s *Consul) DeleteTree(directory string) error {
	if _, err := s.List(directory); err != nil {
		return err
	}
	_, err := s.client.KV().DeleteTree(s.normalize(directory), nil)
	return err
}

// Watch for changes on a "key"
// It returns a channel that will receive changes or pass
// on errors. Upon creation, the current value will first
// be sent to the channel. Providing a non-nil stopCh can
// be used to stop watching.
func (s *Consul) Watch(key string, stopCh <-chan struct{}) (<-chan *store.KVPair, error) {
	kv := s.client.KV()
	watchCh := make(chan *store.KVPair)

	go func() {
		defer close(watchCh)

		// Use a wait time in order to check if we should quit
		// from time to time.
		opts := &api.QueryOptions{WaitTime: DefaultWatchWaitTime}

		for {
			// Check if we should quit
			select {
			case <-stopCh:
				return
			default:
			}

			// Get the key
			pair, meta, err := kv.Get(key, opts)
			if err != nil {
				return
			}

			// If LastIndex didn't change then it means `Get` returned
			// because of the WaitTime and the key didn't changed.
			if opts.WaitIndex == meta.LastIndex {
				continue
			}
			opts.WaitIndex = meta.LastIndex

			// Return the value to the channel
			// FIXME: What happens when a key is deleted?
			if pair != nil {
				watchCh <- &store.KVPair{
					Key:       pair.Key,
					Value:     pair.Value,
					LastIndex: pair.ModifyIndex,
				}
			}
		}
	}()

	return watchCh, nil
}

// WatchTree watches for changes on a "directory"
// It returns a channel that will receive changes or pass
// on errors. Upon creating a watch, the current childs values
// will be sent to the channel .Providing a non-nil stopCh can
// be used to stop watching.
func (s *Consul) WatchTree(directory string, stopCh <-chan struct{}) (<-chan []*store.KVPair, error) {
	kv := s.client.KV()
	watchCh := make(chan []*store.KVPair)

	go func() {
		defer close(watchCh)

		// Use a wait time in order to check if we should quit
		// from time to time.
		opts := &api.QueryOptions{WaitTime: DefaultWatchWaitTime}
		for {
			// Check if we should quit
			select {
			case <-stopCh:
				return
			default:
			}

			// Get all the childrens
			pairs, meta, err := kv.List(directory, opts)
			if err != nil {
				return
			}

			// If LastIndex didn't change then it means `Get` returned
			// because of the WaitTime and the child keys didn't change.
			if opts.WaitIndex == meta.LastIndex {
				continue
			}
			opts.WaitIndex = meta.LastIndex

			// Return children KV pairs to the channel
			kvpairs := []*store.KVPair{}
			for _, pair := range pairs {
				if pair.Key == directory {
					continue
				}
				kvpairs = append(kvpairs, &store.KVPair{
					Key:       pair.Key,
					Value:     pair.Value,
					LastIndex: pair.ModifyIndex,
				})
			}
			watchCh <- kvpairs
		}
	}()

	return watchCh, nil
}

// NewLock returns a handle to a lock struct which can
// be used to provide mutual exclusion on a key
func (s *Consul) NewLock(key string, options *store.LockOptions) (store.Locker, error) {
	lockOpts := &api.LockOptions{
		Key: s.normalize(key),
	}

	lock := &consulLock{}

	ttl := defaultLockTTL

	if options != nil {
		// Set optional TTL on Lock
		if options.TTL != 0 {
			ttl = options.TTL
		}
		// Set optional value on Lock
		if options.Value != nil {
			lockOpts.Value = options.Value
		}
	}

	entry := &api.SessionEntry{
		Behavior:  api.SessionBehaviorRelease, // Release the lock when the session expires
		TTL:       (ttl / 2).String(),         // Consul multiplies the TTL by 2x
		LockDelay: 1 * time.Millisecond,       // Virtually disable lock delay
	}

	// Create the key session
	session, _, err := s.client.Session().Create(entry, nil)
	if err != nil {
		return nil, err
	}

	// Place the session and renew chan on lock
	lockOpts.Session = session
	lock.renewCh = options.RenewLock

	l, err := s.client.LockOpts(lockOpts)
	if err != nil {
		return nil, err
	}

	// Renew the session ttl lock periodically
	s.renewLockSession(entry.TTL, session, options.RenewLock)

	lock.lock = l
	return lock, nil
}

// renewLockSession is used to renew a session Lock, it takes
// a stopRenew chan which is used to explicitely stop the session
// renew process. The renew routine never stops until a signal is
// sent to this channel. If deleting the session fails because the
// connection to the store is lost, it keeps trying to delete the
// session periodically until it can contact the store, this ensures
// that the lock is not maintained indefinitely which ensures liveness
// over safety for the lock when the store becomes unavailable.
func (s *Consul) renewLockSession(initialTTL string, id string, stopRenew chan struct{}) {
	sessionDestroyAttempts := 0
	ttl, err := time.ParseDuration(initialTTL)
	if err != nil {
		return
	}
	go func() {
		for {
			select {
			case <-time.After(ttl / 2):
				entry, _, err := s.client.Session().Renew(id, nil)
				if err != nil {
					// If an error occurs, continue until the
					// session gets destroyed explicitely or
					// the session ttl times out
					continue
				}
				if entry == nil {
					return
				}

				// Handle the server updating the TTL
				ttl, _ = time.ParseDuration(entry.TTL)

			case <-stopRenew:
				// Attempt a session destroy
				_, err := s.client.Session().Destroy(id, nil)
				if err == nil {
					return
				}

				if sessionDestroyAttempts >= MaxSessionDestroyAttempts {
					return
				}

				// We can't destroy the session because the store
				// is unavailable, wait for the session renew period
				sessionDestroyAttempts++
				time.Sleep(ttl / 2)
			}
		}
	}()
}

// Lock attempts to acquire the lock and blocks while
// doing so. It returns a channel that is closed if our
// lock is lost or if an error occurs
func (l *consulLock) Lock(stopChan chan struct{}) (<-chan struct{}, error) {
	return l.lock.Lock(stopChan)
}

// Unlock the "key". Calling unlock while
// not holding the lock will throw an error
func (l *consulLock) Unlock() error {
	if l.renewCh != nil {
		close(l.renewCh)
	}
	return l.lock.Unlock()
}

// AtomicPut put a value at "key" if the key has not been
// modified in the meantime, throws an error if this is the case
func (s *Consul) AtomicPut(key string, value []byte, previous *store.KVPair, options *store.WriteOptions) (bool, *store.KVPair, error) {

	p := &api.KVPair{Key: s.normalize(key), Value: value, Flags: api.LockFlagValue}

	if previous == nil {
		// Consul interprets ModifyIndex = 0 as new key.
		p.ModifyIndex = 0
	} else {
		p.ModifyIndex = previous.LastIndex
	}

	ok, _, err := s.client.KV().CAS(p, nil)
	if err != nil {
		return false, nil, err
	}
	if !ok {
		if previous == nil {
			return false, nil, store.ErrKeyExists
		}
		return false, nil, store.ErrKeyModified
	}

	pair, err := s.Get(key)
	if err != nil {
		return false, nil, err
	}

	return true, pair, nil
}

// AtomicDelete deletes a value at "key" if the key has not
// been modified in the meantime, throws an error if this is the case
func (s *Consul) AtomicDelete(key string, previous *store.KVPair) (bool, error) {
	if previous == nil {
		return false, store.ErrPreviousNotSpecified
	}

	p := &api.KVPair{Key: s.normalize(key), ModifyIndex: previous.LastIndex, Flags: api.LockFlagValue}

	// Extra Get operation to check on the key
	_, err := s.Get(key)
	if err != nil && err == store.ErrKeyNotFound {
		return false, err
	}

	if work, _, err := s.client.KV().DeleteCAS(p, nil); err != nil {
		return false, err
	} else if !work {
		return false, store.ErrKeyModified
	}

	return true, nil
}

// Close closes the client connection
func (s *Consul) Close() {
	return
}

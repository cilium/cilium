package multistep

import "sync"

// Add context to state bag to prevent changing step signature

// StateBag holds the state that is used by the Runner and Steps. The
// StateBag implementation must be safe for concurrent access.
type StateBag interface {
	Get(string) interface{}
	GetOk(string) (interface{}, bool)
	Put(string, interface{})
	Remove(string)
}

// BasicStateBag implements StateBag by using a normal map underneath
// protected by a RWMutex.
type BasicStateBag struct {
	data map[string]interface{}
	l    sync.RWMutex
	once sync.Once
}

func (b *BasicStateBag) Get(k string) interface{} {
	result, _ := b.GetOk(k)
	return result
}

func (b *BasicStateBag) GetOk(k string) (interface{}, bool) {
	b.l.RLock()
	defer b.l.RUnlock()

	result, ok := b.data[k]
	return result, ok
}

func (b *BasicStateBag) Put(k string, v interface{}) {
	b.l.Lock()
	defer b.l.Unlock()

	// Make sure the map is initialized one time, on write
	b.once.Do(func() {
		b.data = make(map[string]interface{})
	})

	// Write the data
	b.data[k] = v
}

func (b *BasicStateBag) Remove(k string) {
	delete(b.data, k)
}

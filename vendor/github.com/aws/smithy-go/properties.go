package smithy

// PropertiesReader provides an interface for reading metadata from the
// underlying metadata container.
type PropertiesReader interface {
	Get(key interface{}) interface{}
}

// Properties provides storing and reading metadata values. Keys may be any
// comparable value type. Get and set will panic if key is not a comparable
// value type.
//
// Properties uses lazy initialization, and Set method must be called as an
// addressable value, or pointer. Not doing so may cause key/value pair to not
// be set.
type Properties struct {
	values map[interface{}]interface{}
}

// Get attempts to retrieve the value the key points to. Returns nil if the
// key was not found.
//
// Panics if key type is not comparable.
func (m *Properties) Get(key interface{}) interface{} {
	return m.values[key]
}

// Set stores the value pointed to by the key. If a value already exists at
// that key it will be replaced with the new value.
//
// Set method must be called as an addressable value, or pointer. If Set is not
// called as an addressable value or pointer, the key value pair being set may
// be lost.
//
// Panics if the key type is not comparable.
func (m *Properties) Set(key, value interface{}) {
	if m.values == nil {
		m.values = map[interface{}]interface{}{}
	}
	m.values[key] = value
}

// Has returns whether the key exists in the metadata.
//
// Panics if the key type is not comparable.
func (m *Properties) Has(key interface{}) bool {
	if m.values == nil {
		return false
	}
	_, ok := m.values[key]
	return ok
}

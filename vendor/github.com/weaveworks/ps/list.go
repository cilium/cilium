package ps

// List is a persistent list of possibly heterogenous values.
type List interface {
	// IsNil returns true if the list is empty
	IsNil() bool

	// Cons returns a new list with val as the head
	Cons(val interface{}) List

	// Head returns the first element of the list;
	// panics if the list is empty
	Head() interface{}

	// Tail returns a list with all elements except the head;
	// panics if the list is empty
	Tail() List

	// Size returns the list's length.  This takes O(1) time.
	Size() int

	// ForEach executes a callback for each value in the list.
	ForEach(f func(interface{}))

	// Reverse returns a list whose elements are in the opposite order as
	// the original list.
	Reverse() List
}

// Immutable (i.e. persistent) list
type list struct {
	depth int // the number of nodes after, and including, this one
	value interface{}
	tail  *list
}

// An empty list shared by all lists
var nilList = &list{}

// NewList returns a new, empty list.  The result is a singly linked
// list implementation.  All lists share an empty tail, so allocating
// empty lists is efficient in time and memory.
func NewList() List {
	return nilList
}

func (self *list) IsNil() bool {
	return self == nilList
}

func (self *list) Size() int {
	return self.depth
}

func (tail *list) Cons(val interface{}) List {
	var xs list
	xs.depth = tail.depth + 1
	xs.value = val
	xs.tail = tail
	return &xs
}

func (self *list) Head() interface{} {
	if self.IsNil() {
		panic("Called Head() on an empty list")
	}

	return self.value
}

func (self *list) Tail() List {
	if self.IsNil() {
		panic("Called Tail() on an empty list")
	}

	return self.tail
}

// ForEach executes a callback for each value in the list
func (self *list) ForEach(f func(interface{})) {
	if self.IsNil() {
		return
	}
	f(self.Head())
	self.Tail().ForEach(f)
}

// Reverse returns a list with elements in opposite order as this list
func (self *list) Reverse() List {
	reversed := NewList()
	self.ForEach(func(v interface{}) { reversed = reversed.Cons(v) })
	return reversed
}

package _generated

//go:generate msgp

type Issue102 struct{}

type Issue102deep struct {
	A int
	X struct{}
	Y struct{}
	Z int
}

//msgp:tuple Issue102Tuple

type Issue102Tuple struct{}

//msgp:tuple Issue102TupleDeep

type Issue102TupleDeep struct {
	A int
	X struct{}
	Y struct{}
	Z int
}

type Issue102Uses struct {
	Nested    Issue102
	NestedPtr *Issue102
}

//msgp:tuple Issue102TupleUsesTuple

type Issue102TupleUsesTuple struct {
	Nested    Issue102Tuple
	NestedPtr *Issue102Tuple
}

//msgp:tuple Issue102TupleUsesMap

type Issue102TupleUsesMap struct {
	Nested    Issue102
	NestedPtr *Issue102
}

type Issue102MapUsesTuple struct {
	Nested    Issue102Tuple
	NestedPtr *Issue102Tuple
}

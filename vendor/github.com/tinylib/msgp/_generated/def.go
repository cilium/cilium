package _generated

import (
	"github.com/tinylib/msgp/msgp"
	"os"
	"time"
)

//go:generate msgp -o generated.go

// All of the struct
// definitions in this
// file are fed to the code
// generator when `make test` is
// called, followed by an
// invocation of `go test -v` in this
// directory. A simple way of testing
// a struct definition is
// by adding it to this file.

type Block [32]byte

// tests edge-cases with
// compiling size compilation.
type X struct {
	Values    [32]byte    // should compile to 32*msgp.ByteSize; encoded as Bin
	More      Block       // should be identical to the above
	Others    [][32]int32 // should compile to len(x.Others)*32*msgp.Int32Size
	Matrix    [][]int32   // should not optimize
	ManyFixed []Fixed
}

// test fixed-size struct
// size compilation
type Fixed struct {
	A float64
	B bool
}

type TestType struct {
	F   *float64          `msg:"float"`
	Els map[string]string `msg:"elements"`
	Obj struct {          // test anonymous struct
		ValueA string `msg:"value_a"`
		ValueB []byte `msg:"value_b"`
	} `msg:"object"`
	Child    *TestType   `msg:"child"`
	Time     time.Time   `msg:"time"`
	Any      interface{} `msg:"any"`
	Appended msgp.Raw    `msg:"appended"`
	Num      msgp.Number `msg:"num"`
	Slice1   []string
	Slice2   []string
	SlicePtr *[]string
}

//msgp:tuple Object
type Object struct {
	ObjectNo string   `msg:"objno"`
	Slice1   []string `msg:"slice1"`
	Slice2   []string `msg:"slice2"`
	MapMap   map[string]map[string]string
}

//msgp:tuple TestBench

type TestBench struct {
	Name     string
	BirthDay time.Time
	Phone    string
	Siblings int
	Spouse   bool
	Money    float64
}

//msgp:tuple TestFast

type TestFast struct {
	Lat, Long, Alt float64 // test inline decl
	Data           []byte
}

// Test nested aliases
type FastAlias TestFast
type AliasContainer struct {
	Fast FastAlias
}

// Test dependency resolution
type IntA int
type IntB IntA
type IntC IntB

type TestHidden struct {
	A   string
	B   []float64
	Bad func(string) bool // This results in a warning: field "Bad" unsupported
}

type Embedded struct {
	*Embedded   // test embedded field
	Children    []Embedded
	PtrChildren []*Embedded
	Other       string
}

const eight = 8

type Things struct {
	Cmplx complex64                         `msg:"complex"` // test slices
	Vals  []int32                           `msg:"values"`
	Arr   [msgp.ExtensionPrefixSize]float64 `msg:"arr"`            // test const array and *ast.SelectorExpr as array size
	Arr2  [4]float64                        `msg:"arr2"`           // test basic lit array
	Ext   *msgp.RawExtension                `msg:"ext,extension"`  // test extension
	Oext  msgp.RawExtension                 `msg:"oext,extension"` // test extension reference
}

//msgp:shim SpecialID as:[]byte using:toBytes/fromBytes

type SpecialID string
type TestObj struct{ ID1, ID2 SpecialID }

func toBytes(id SpecialID) []byte   { return []byte(string(id)) }
func fromBytes(id []byte) SpecialID { return SpecialID(string(id)) }

type MyEnum byte

const (
	A MyEnum = iota
	B
	C
	D
	invalid
)

// test shim directive (below)

//msgp:shim MyEnum as:string using:(MyEnum).String/myenumStr

//msgp:shim *os.File as:string using:filetostr/filefromstr

func filetostr(f *os.File) string {
	return f.Name()
}

func filefromstr(s string) *os.File {
	f, _ := os.Open(s)
	return f
}

func (m MyEnum) String() string {
	switch m {
	case A:
		return "A"
	case B:
		return "B"
	case C:
		return "C"
	case D:
		return "D"
	default:
		return "<invalid>"
	}
}

func myenumStr(s string) MyEnum {
	switch s {
	case "A":
		return A
	case "B":
		return B
	case "C":
		return C
	case "D":
		return D
	default:
		return invalid
	}
}

// test pass-specific directive
//msgp:decode ignore Insane

type Insane [3]map[string]struct{ A, B CustomInt }

type Custom struct {
	Bts   CustomBytes          `msg:"bts"`
	Mp    map[string]*Embedded `msg:"mp"`
	Enums []MyEnum             `msg:"enums"` // test explicit enum shim
	Some  FileHandle           `msg:file_handle`
}

type Files []*os.File

type FileHandle struct {
	Relevent Files  `msg:"files"`
	Name     string `msg:"name"`
}

type CustomInt int
type CustomBytes []byte

type Wrapper struct {
	Tree *Tree
}

type Tree struct {
	Children []Tree
	Element  int
	Parent   *Wrapper
}

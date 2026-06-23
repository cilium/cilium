package wasm

// Exception represents a thrown WebAssembly exception.
type Exception struct {
	// Tag is the tag instance that was thrown.
	Tag *TagInstance
	// Params holds the argument values matching the tag's function type params.
	Params []uint64
}

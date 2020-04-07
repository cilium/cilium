package pgs

// A PostProcessor modifies the output of an Artifact before final rendering.
type PostProcessor interface {
	// Match returns true if the PostProcess should be applied to the Artifact.
	// Process is called immediately after Match for the same Artifact.
	Match(a Artifact) bool

	// Process receives the rendered artifact and returns the processed bytes or
	// an error if something goes wrong.
	Process(in []byte) ([]byte, error)
}

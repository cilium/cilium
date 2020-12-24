package ini

import (
	"io"
	"os"
)

// OpenFile takes a path to a given file, and will open  and parse
// that file.
func OpenFile(path string) (Sections, error) {
	f, err := os.Open(path)
	if err != nil {
		return Sections{}, &UnableToReadFile{Err: err}
	}
	defer f.Close()

	return Parse(f, path)
}

// Parse will parse the given file using the shared config
// visitor.
func Parse(f io.Reader, path string) (Sections, error) {
	tree, err := ParseAST(f)
	if err != nil {
		return Sections{}, err
	}

	v := NewDefaultVisitor(path)
	if err = Walk(tree, v); err != nil {
		return Sections{}, err
	}

	return v.Sections, nil
}

// ParseBytes will parse the given bytes and return the parsed sections.
func ParseBytes(b []byte) (Sections, error) {
	tree, err := ParseASTBytes(b)
	if err != nil {
		return Sections{}, err
	}

	v := NewDefaultVisitor("")
	if err = Walk(tree, v); err != nil {
		return Sections{}, err
	}

	return v.Sections, nil
}

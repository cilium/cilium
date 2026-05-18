/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package markers

import (
	"go/ast"
	"go/token"
	"strings"
	"sync"

	"sigs.k8s.io/controller-tools/pkg/loader"
)

// Collector collects and parses marker comments defined in the registry
// from package source code.  If no registry is provided, an empty one will
// be initialized on the first call to MarkersInPackage.
type Collector struct {
	*Registry

	byPackage map[*loader.Package]map[ast.Node]MarkerValues
	mu        sync.Mutex
}

// MarkerValues are all the values for some set of markers.
type MarkerValues map[string][]any

// Get fetches the first value that for the given marker, returning
// nil if no values are available.
func (v MarkerValues) Get(name string) any {
	vals := v[name]
	if len(vals) == 0 {
		return nil
	}
	return vals[0]
}

func (c *Collector) init() {
	if c.Registry == nil {
		c.Registry = &Registry{}
	}
	if c.byPackage == nil {
		c.byPackage = make(map[*loader.Package]map[ast.Node]MarkerValues)
	}
}

// MarkersInPackage computes the marker values by node for the given package.  Results
// are cached by package ID, so this is safe to call repeatedly from different functions.
// Each file in the package is treated as a distinct node.
//
// We consider a marker to be associated with a given AST node if either of the following are true:
//
// - it's in the Godoc for that AST node
//
//   - it's in the closest non-godoc comment group above that node,
//     *and* that node is a type or field node, *and* [it's either
//     registered as type-level *or* it's not registered as being
//     package-level]
//
//   - it's not in the Godoc of a node, doesn't meet the above criteria, and
//     isn't in a struct definition (in which case it's package-level)
func (c *Collector) MarkersInPackage(pkg *loader.Package) (map[ast.Node]MarkerValues, error) {
	c.mu.Lock()
	c.init()
	if markers, exist := c.byPackage[pkg]; exist {
		c.mu.Unlock()
		return markers, nil
	}
	// unlock early, it's ok if we do a bit extra work rather than locking while we're working
	c.mu.Unlock()

	pkg.NeedSyntax()
	nodeMarkersRaw := c.associatePkgMarkers(pkg)
	markers, err := c.parseMarkersInPackage(nodeMarkersRaw)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.byPackage[pkg] = markers
	return markers, nil
}

// parseMarkersInPackage parses the given raw marker comments into output values using the registry.
func (c *Collector) parseMarkersInPackage(nodeMarkersRaw map[ast.Node][]markerComment) (map[ast.Node]MarkerValues, error) {
	var errors []error
	nodeMarkerValues := make(map[ast.Node]MarkerValues)
	for node, markersRaw := range nodeMarkersRaw {
		var target TargetType
		switch node.(type) {
		case *ast.File:
			target = DescribesPackage
		case *ast.Field:
			target = DescribesField
		default:
			target = DescribesType
		}
		markerVals := make(map[string][]any)
		for _, markerRaw := range markersRaw {
			markerText := markerRaw.Text()
			def := c.Registry.Lookup(markerText, target)
			if def == nil {
				continue
			}
			val, err := def.Parse(markerText)
			if err != nil {
				errors = append(errors, loader.ErrFromNode(err, markerRaw))
				continue
			}
			markerVals[def.Name] = append(markerVals[def.Name], val)
		}
		nodeMarkerValues[node] = markerVals
	}

	return nodeMarkerValues, loader.MaybeErrList(errors)
}

// associatePkgMarkers associates markers with AST nodes in the given package.
func (c *Collector) associatePkgMarkers(pkg *loader.Package) map[ast.Node][]markerComment {
	nodeMarkers := make(map[ast.Node][]markerComment)
	for _, file := range pkg.Syntax {
		fileNodeMarkers := c.associateFileMarkers(file)
		for node, markers := range fileNodeMarkers {
			nodeMarkers[node] = append(nodeMarkers[node], markers...)
		}
	}

	return nodeMarkers
}

// associateFileMarkers associates markers with AST nodes in the given file.
func (c *Collector) associateFileMarkers(file *ast.File) map[ast.Node][]markerComment {
	// grab all the raw marker comments by node
	visitor := markerSubVisitor{
		collectPackageLevel: true,
		markerVisitor: &markerVisitor{
			nodeMarkers: make(map[ast.Node][]markerComment),
			allComments: file.Comments,
		},
	}
	ast.Walk(visitor, file)

	// grab the last package-level comments at the end of the file (if any)
	lastFileMarkers := visitor.markersBetween(false, visitor.commentInd, len(visitor.allComments))
	visitor.pkgMarkers = append(visitor.pkgMarkers, lastFileMarkers...)

	// figure out if any type-level markers are actually package-level markers
	for node, markers := range visitor.nodeMarkers {
		_, isType := node.(*ast.TypeSpec)
		if !isType {
			continue
		}
		endOfMarkers := 0
		for _, marker := range markers {
			if marker.fromGodoc {
				// markers from godoc are never package level
				markers[endOfMarkers] = marker
				endOfMarkers++
				continue
			}
			markerText := marker.Text()
			typeDef := c.Registry.Lookup(markerText, DescribesType)
			if typeDef != nil {
				// prefer assuming type-level markers
				markers[endOfMarkers] = marker
				endOfMarkers++
				continue
			}
			def := c.Registry.Lookup(markerText, DescribesPackage)
			if def == nil {
				// assume type-level unless proven otherwise
				markers[endOfMarkers] = marker
				endOfMarkers++
				continue
			}
			// it's package-level, since a package-level definition exists
			visitor.pkgMarkers = append(visitor.pkgMarkers, marker)
		}
		visitor.nodeMarkers[node] = markers[:endOfMarkers] // re-set after trimming the package markers
	}
	visitor.nodeMarkers[file] = visitor.pkgMarkers

	return visitor.nodeMarkers
}

// markerComment is an AST comment that contains a marker.
// It may or may not be from a Godoc comment, which affects
// marker re-associated (from type-level to package-level)
type markerComment struct {
	*ast.Comment
	fromGodoc bool
}

// Text returns the text of the marker, stripped of the comment
// marker and leading spaces, as should be passed to Registry.Lookup
// and Registry.Parse.
func (c markerComment) Text() string {
	return strings.TrimSpace(c.Comment.Text[2:])
}

// markerVisistor visits AST nodes, recording markers associated with each node.
type markerVisitor struct {
	allComments []*ast.CommentGroup
	commentInd  int

	declComments         []markerComment
	lastLineCommentGroup *ast.CommentGroup

	pkgMarkers  []markerComment
	nodeMarkers map[ast.Node][]markerComment
}

// isMarkerComment checks that the given comment is a single-line (`//`)
// comment and it's first non-space content is `+`.
func isMarkerComment(comment string) bool {
	if comment[0:2] != "//" {
		return false
	}
	stripped := strings.TrimSpace(comment[2:])
	if len(stripped) < 1 || stripped[0] != '+' {
		return false
	}
	return true
}

// markersBetween grabs the markers between the given indicies in the list of all comments.
func (v *markerVisitor) markersBetween(fromGodoc bool, start, end int) []markerComment {
	if start < 0 || end < 0 {
		return nil
	}
	var res []markerComment
	for i := start; i < end; i++ {
		commentGroup := v.allComments[i]
		for _, comment := range commentGroup.List {
			if !isMarkerComment(comment.Text) {
				continue
			}
			res = append(res, markerComment{Comment: comment, fromGodoc: fromGodoc})
		}
	}
	return res
}

type markerSubVisitor struct {
	*markerVisitor
	node                ast.Node
	collectPackageLevel bool
}

// Visit collects markers for each node in the AST, optionally
// collecting unassociated markers as package-level.
func (v markerSubVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		// end of the node, so we might need to advance comments beyond the end
		// of the block if we don't want to collect package-level markers in
		// this block.

		if !v.collectPackageLevel {
			if v.commentInd < len(v.allComments) {
				lastCommentInd := v.commentInd
				nextGroup := v.allComments[lastCommentInd]
				for nextGroup.Pos() < v.node.End() {
					lastCommentInd++
					if lastCommentInd >= len(v.allComments) {
						// after the increment so our decrement below still makes sense
						break
					}
					nextGroup = v.allComments[lastCommentInd]
				}
				v.commentInd = lastCommentInd
			}
		}

		return nil
	}

	// skip comments on the same line as the previous node
	// making sure to double-check for the case where we've gone past the end of the comments
	// but still have to finish up typespec-gendecl association (see below).
	if v.lastLineCommentGroup != nil && v.commentInd < len(v.allComments) && v.lastLineCommentGroup.Pos() == v.allComments[v.commentInd].Pos() {
		v.commentInd++
	}

	// stop visiting if there are no more comments in the file
	// NB(directxman12): we can't just stop immediately, because we
	// still need to check if there are typespecs associated with gendecls.
	var markerCommentBlock []markerComment
	var docCommentBlock []markerComment
	lastCommentInd := v.commentInd
	if v.commentInd < len(v.allComments) {
		// figure out the first comment after the node in question...
		nextGroup := v.allComments[lastCommentInd]
		for nextGroup.Pos() < node.Pos() {
			lastCommentInd++
			if lastCommentInd >= len(v.allComments) {
				// after the increment so our decrement below still makes sense
				break
			}
			nextGroup = v.allComments[lastCommentInd]
		}
		lastCommentInd-- // ...then decrement to get the last comment before the node in question

		// figure out the godoc comment so we can deal with it separately
		var docGroup *ast.CommentGroup
		docGroup, v.lastLineCommentGroup = associatedCommentsFor(node)

		// find the last comment group that's not godoc
		markerCommentInd := lastCommentInd
		if docGroup != nil && v.allComments[markerCommentInd].Pos() == docGroup.Pos() {
			markerCommentInd--
		}

		// check if we have freestanding package markers,
		// and find the markers in our "closest non-godoc" comment block,
		// plus our godoc comment block
		if markerCommentInd >= v.commentInd {
			if v.collectPackageLevel {
				// assume anything between the comment ind and the marker ind (not including it)
				// are package-level
				v.pkgMarkers = append(v.pkgMarkers, v.markersBetween(false, v.commentInd, markerCommentInd)...)
			}
			markerCommentBlock = v.markersBetween(false, markerCommentInd, markerCommentInd+1)
			docCommentBlock = v.markersBetween(true, markerCommentInd+1, lastCommentInd+1)
		} else {
			docCommentBlock = v.markersBetween(true, markerCommentInd+1, lastCommentInd+1)
		}
	}

	resVisitor := markerSubVisitor{
		collectPackageLevel: false, // don't collect package level by default
		markerVisitor:       v.markerVisitor,
		node:                node,
	}

	// associate those markers with a node
	switch typedNode := node.(type) {
	case *ast.GenDecl:
		// save the comments associated with the gen-decl if it's a single-line type decl
		if typedNode.Lparen != token.NoPos || typedNode.Tok != token.TYPE {
			// not a single-line type spec, treat them as free comments
			v.pkgMarkers = append(v.pkgMarkers, markerCommentBlock...)
			break
		}
		// save these, we'll need them when we encounter the actual type spec
		v.declComments = append(v.declComments, markerCommentBlock...)
		v.declComments = append(v.declComments, docCommentBlock...)
	case *ast.TypeSpec:
		// add in comments attributed to the gen-decl, if any,
		// as well as comments associated with the actual type
		v.nodeMarkers[node] = append(v.nodeMarkers[node], v.declComments...)
		v.nodeMarkers[node] = append(v.nodeMarkers[node], markerCommentBlock...)
		v.nodeMarkers[node] = append(v.nodeMarkers[node], docCommentBlock...)

		v.declComments = nil
		v.collectPackageLevel = false // don't collect package-level inside type structs
	case *ast.Field:
		v.nodeMarkers[node] = append(v.nodeMarkers[node], markerCommentBlock...)
		v.nodeMarkers[node] = append(v.nodeMarkers[node], docCommentBlock...)
	case *ast.File:
		v.pkgMarkers = append(v.pkgMarkers, markerCommentBlock...)
		v.pkgMarkers = append(v.pkgMarkers, docCommentBlock...)

		// collect markers in root file scope
		resVisitor.collectPackageLevel = true
	default:
		// assume markers before anything else are package-level markers,
		// *but* don't include any markers in godoc
		if v.collectPackageLevel {
			v.pkgMarkers = append(v.pkgMarkers, markerCommentBlock...)
		}
	}

	// increment the comment ind so that we start at the right place for the next node
	v.commentInd = lastCommentInd + 1

	return resVisitor
}

// associatedCommentsFor returns the doc comment group (if relevant and present) and end-of-line comment
// (again if relevant and present) for the given AST node.
func associatedCommentsFor(node ast.Node) (docGroup *ast.CommentGroup, lastLineCommentGroup *ast.CommentGroup) {
	switch typedNode := node.(type) {
	case *ast.Field:
		docGroup = typedNode.Doc
		lastLineCommentGroup = typedNode.Comment
	case *ast.File:
		docGroup = typedNode.Doc
	case *ast.FuncDecl:
		docGroup = typedNode.Doc
	case *ast.GenDecl:
		docGroup = typedNode.Doc
	case *ast.ImportSpec:
		docGroup = typedNode.Doc
		lastLineCommentGroup = typedNode.Comment
	case *ast.TypeSpec:
		docGroup = typedNode.Doc
		lastLineCommentGroup = typedNode.Comment
	case *ast.ValueSpec:
		docGroup = typedNode.Doc
		lastLineCommentGroup = typedNode.Comment
	default:
		lastLineCommentGroup = nil
	}

	return docGroup, lastLineCommentGroup
}

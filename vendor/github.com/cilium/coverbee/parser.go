package coverbee

import (
	"fmt"
	"sort"

	"github.com/alecthomas/participle/v2/lexer"
	"github.com/cilium/coverbee/pkg/cparser"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/cover"
)

// CTranslationUnitToBlocks turns a TranslationUnit into a list of cover blocks and a map which can be used to see
// which AST nodes generated which blocks.
func CTranslationUnitToBlocks(tu *cparser.TranslationUnit) ([]*CoverBlock, map[cparser.ASTNode][]*CoverBlock) {
	var blocks []*CoverBlock

	appendBlock := func(start, end lexer.Position, numStmt int) *CoverBlock {
		block := &CoverBlock{
			Filename: start.Filename,
			ProfileBlock: cover.ProfileBlock{
				StartLine: start.Line,
				StartCol:  start.Column,
				EndLine:   end.Line,
				EndCol:    end.Column,
				NumStmt:   numStmt,
			},
		}
		blocks = append(blocks, block)
		return block
	}

	nodeToBlockMap := make(map[cparser.ASTNode][]*CoverBlock)

	cparser.VisitDepthFirst(tu, func(node cparser.ASTNode, _ []cparser.ASTNode) {
		switch node := node.(type) {
		case *cparser.ExpressionStatement, *cparser.JumpStatement:
			block := appendBlock(node.GetHead(), node.GetTail(), 1)
			nodeToBlockMap[node] = append(nodeToBlockMap[node], block)

		case *cparser.SelectionStatement:
			block := appendBlock(node.GetHead(), node.ClosingBracket, 1)
			nodeToBlockMap[node] = append(nodeToBlockMap[node], block)

			if node.ElseToken != nil {
				elseEnd := *node.ElseToken
				elseEnd.Advance("else")
				block = appendBlock(*node.ElseToken, elseEnd, 1)
				nodeToBlockMap[node] = append(nodeToBlockMap[node], block)
			}

		case *cparser.ForStatement:
			block := appendBlock(node.GetHead(), node.ClosingBracket, 1)
			nodeToBlockMap[node] = append(nodeToBlockMap[node], block)

		case *cparser.WhileStatement:
			block := appendBlock(node.GetHead(), node.ClosingBracket, 1)
			nodeToBlockMap[node] = append(nodeToBlockMap[node], block)
		}
	})

	return blocks, nodeToBlockMap
}

// SourceCodeInterpolation parses all files referenced in the coverage block list and the additional file paths as C
// code. It then uses the parsed code to construct coverage blocks from the source code instead of the compiled
// object. This results in a more "complete" negative profile since it also will include lines which the compiler
// tends to optimize out. It then applies the measured coverage to the source blocks. Lastly it will infer / interpolate
// which lines of code must also have been evaluated given the AST and the coverage blocklist. The intended goal being
// a more accurate report.
func SourceCodeInterpolation(coverageBlockList [][]CoverBlock, additionalFilePaths []string) ([][]CoverBlock, error) {
	uniqueFiles := BlockListFilePaths(coverageBlockList)

	for _, additionalPath := range additionalFilePaths {
		i := sort.SearchStrings(uniqueFiles, additionalPath)
		if i < len(uniqueFiles) && uniqueFiles[i] == additionalPath {
			continue
		}

		// Insert sorted
		uniqueFiles = append(uniqueFiles, "")
		copy(uniqueFiles[i+1:], uniqueFiles[i:])
		uniqueFiles[i] = additionalPath
	}

	// Base blocks contains blocks for all possible paths of a file, not just the onces that made it into the final
	// binary.
	baseBlocks := make(map[string][]*CoverBlock)
	nodeToBlockMaps := make(map[string]map[cparser.ASTNode][]*CoverBlock)
	translationUnits := make(map[string]*cparser.TranslationUnit)
	for _, filepath := range uniqueFiles {
		tu, err := cparser.ParseFile(filepath)
		if err != nil {
			return nil, fmt.Errorf("cparser parse file: %w", err)
		}
		translationUnits[filepath] = tu

		baseBlocks[filepath], nodeToBlockMaps[filepath] = CTranslationUnitToBlocks(tu)
	}

	// Loop over all blocks that we got from the coverage. Apply the results to the baseBlocks.
	for _, coverBlocks := range coverageBlockList {
		for _, coverBlock := range coverBlocks {
			fileBlocks := baseBlocks[coverBlock.Filename]

			for i := range fileBlocks {
				fileBlock := fileBlocks[i]

				if blocksOverlap(fileBlock.ProfileBlock, coverBlock.ProfileBlock) {
					fileBlock.ProfileBlock.Count += coverBlock.ProfileBlock.Count
				}
			}
		}
	}

	// Coverage inference.
	// The compiler can optimize out some lines of code or not include them in the debug info. In this step we attempt
	// to infer which lines are implicitly covered as well. We know that adjacent expressions execute after each other
	// as long as no branching occurs.
	for filepath := range baseBlocks {
		tu := translationUnits[filepath]
		nodeToBlocks := nodeToBlockMaps[filepath]

		// Walk the AST
		cparser.VisitDepthFirst(tu, func(node cparser.ASTNode, parents []cparser.ASTNode) {
			blocks := nodeToBlocks[node]
			maxCnt := 0
			for _, block := range blocks {
				if maxCnt < block.ProfileBlock.Count {
					maxCnt = block.ProfileBlock.Count
				}
			}
			if maxCnt == 0 {
				return
			}

			// If one of the blocks associated with this node has been covered, walk up to the parents
			for i := len(parents) - 1; i >= 0; i-- {
				parent := parents[i]
				switch parent := parent.(type) {
				case *cparser.CompoundStatement:
					// example:
					// {
					//   abc++;         // not covered
					//   char def = 1;  // covered (`node`)
					//   def++;			// not covered
					// }

					if i+1 >= len(parents) {
						break
					}

					originBlock, ok := parents[i+1].(*cparser.BlockItem)
					if !ok {
						return
					}
					originIdx := slices.Index(parent.BlockItems, originBlock)
					if originIdx == -1 {
						break
					}

					// Walk up
					for ii := originIdx - 1; ii >= 0; ii-- {
						sibling := parent.BlockItems[ii]
						// If this sibling is a jump or labeled statement, we can't guarantee that the statement
						// above that was executed together with the one we are currently evaluating.
						if sibling.Statement.JumpStatement != nil || sibling.Statement.LabeledStatement != nil {
							break
						}

						if sibling.Statement.ExpressionStatement != nil {
							siblingBlocks := nodeToBlocks[sibling.Statement.ExpressionStatement]
							for _, siblingBlock := range siblingBlocks {
								if siblingBlock.ProfileBlock.Count < maxCnt {
									siblingBlock.ProfileBlock.Count = maxCnt
								}
							}
						}
					}

					// Walk down
					for ii := originIdx + 1; ii < len(parent.BlockItems); ii++ {
						sibling := parent.BlockItems[ii]
						// If this sibling is a jump, or selection statement, we can't guarantee that the
						// statement after it will have executed together with the node we are currently evaluating
						if sibling.Statement.JumpStatement != nil ||
							sibling.Statement.SelectionStatement != nil {
							break
						}

						if sibling.Statement.ExpressionStatement != nil {
							siblingBlocks := nodeToBlocks[sibling.Statement.ExpressionStatement]
							for _, siblingBlock := range siblingBlocks {
								if siblingBlock.ProfileBlock.Count < maxCnt {
									siblingBlock.ProfileBlock.Count = maxCnt
								}
							}
						}
					}

				case *cparser.SelectionStatement:
					if i+1 >= len(parents) {
						break
					}

					nodes := nodeToBlocks[parent]

					originStmt, ok := parents[i+1].(*cparser.Statement)
					if !ok {
						return
					}
					if parent.IfBody == originStmt || parent.SwitchBody == originStmt {
						if nodes[0].ProfileBlock.Count < maxCnt {
							nodes[0].ProfileBlock.Count = maxCnt
						}
					}

					if parent.ElseBody == originStmt {
						if nodes[1].ProfileBlock.Count < maxCnt {
							nodes[1].ProfileBlock.Count = maxCnt
						}
					}
				}
			}
		})
	}

	var outBlocks [][]CoverBlock
	for _, blocks := range baseBlocks {
		derefBlocks := make([]CoverBlock, len(blocks))
		for i := range blocks {
			derefBlocks[i] = *blocks[i]
		}
		outBlocks = append(outBlocks, derefBlocks)
	}

	return outBlocks, nil
}

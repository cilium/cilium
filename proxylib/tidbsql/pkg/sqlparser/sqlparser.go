package sqlparser

import (
	"fmt"
	"github.com/pingcap/tidb/parser"
	"github.com/pingcap/tidb/parser/ast"
	_ "github.com/pingcap/tidb/parser/test_driver"
)

func parse(sql string) (ast.StmtNode, error) {
	p := parser.New()

	stmtNodes, _, err := p.Parse(sql, "", "")
	if err != nil {
		return nil, err
	}

	return stmtNodes[0], nil
}

func GetDatabaseTables(sql string) (action string, database string, table string, err error) {
	astNode, err := parse(sql)
	if err != nil {
		return "", "", "", fmt.Errorf("parse error: %v", err.Error())
	}

	switch astNode.(type) {
	case *ast.SelectStmt:
		table := astNode.(*ast.SelectStmt).From.TableRefs.Left.(*ast.TableSource).Source.(*ast.TableName)
		return "select", table.Schema.String(), table.Name.String(), nil
	default:
		return "", "", "", fmt.Errorf("not supported action: %T", astNode)
	}
	return
}

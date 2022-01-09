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

	switch v := astNode.(type) {
	case *ast.SelectStmt:
		table := v.From.TableRefs.Left.(*ast.TableSource).Source.(*ast.TableName)
		return "select", table.Schema.String(), table.Name.String(), nil
	case *ast.InsertStmt:
		table := v.Table.TableRefs.Left.(*ast.TableSource).Source.(*ast.TableName)
		return "insert", table.Schema.String(), table.Name.String(), nil
	case *ast.UpdateStmt:
		table := v.TableRefs.TableRefs.Left.(*ast.TableSource).Source.(*ast.TableName)
		return "update", table.Schema.String(), table.Name.String(), nil
	case *ast.DeleteStmt:
		table := v.TableRefs.TableRefs.Left.(*ast.TableSource).Source.(*ast.TableName)
		return "delete", table.Schema.String(), table.Name.String(), nil
	default:
		return "", "", "", fmt.Errorf("not supported action: %T", astNode)
	}
	return "", "", "", fmt.Errorf("sql parser error")
}

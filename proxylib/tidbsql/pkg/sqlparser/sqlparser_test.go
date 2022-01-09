package sqlparser

import (
	"testing"

	_ "github.com/pingcap/tidb/parser/test_driver"
)

func TestGetDatabaseTables(t *testing.T) {
	type args struct {
		sql string
	}
	tests := []struct {
		name         string
		args         args
		wantAction   string
		wantDatabase string
		wantTable    string
		wantErr      bool
	}{
		{
			name: "select",
			args: args{
				sql: "select a, b from d.t",
			},
			wantAction:   "select",
			wantDatabase: "d",
			wantTable:    "t",
			wantErr:      false,
		},
		{
			name: "insert",
			args: args{
				sql: "insert into d.t values(1)",
			},
			wantAction:   "insert",
			wantDatabase: "d",
			wantTable:    "t",
			wantErr:      false,
		},
		{
			name: "update",
			args: args{
				sql: "update d.t set t=1 where t=1",
			},
			wantAction:   "update",
			wantDatabase: "d",
			wantTable:    "t",
			wantErr:      false,
		},
		{
			name: "delete",
			args: args{
				sql: "delete from d.t where t=1",
			},
			wantAction:   "delete",
			wantDatabase: "d",
			wantTable:    "t",
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAction, gotDatabase, gotTable, err := GetDatabaseTables(tt.args.sql)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDatabaseTables() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotAction != tt.wantAction {
				t.Errorf("GetDatabaseTables() gotAction = %v, want %v", gotAction, tt.wantAction)
			}
			if gotDatabase != tt.wantDatabase {
				t.Errorf("GetDatabaseTables() gotDatabase = %v, want %v", gotDatabase, tt.wantDatabase)
			}
			if gotTable != tt.wantTable {
				t.Errorf("GetDatabaseTables() gotTable = %v, want %v", gotTable, tt.wantTable)
			}
		})
	}
}

package pgproxy

import (
	"github.com/davecgh/go-spew/spew"
	"reflect"
	"testing"
)

func Test_splitQueries(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: `Simple`,
			sql:  `SELECT 1; SELECT 2;`,
			want: []string{
				`SELECT 1`,
				`SELECT 2`,
			},
		},
		{
			name: `Simple single quote`,
			sql:  `SELECT '1'; SELECT '2';`,
			want: []string{
				`SELECT '1'`,
				`SELECT '2'`,
			},
		},
		{
			name: `Simple double quote`,
			sql:  `SELECT "1"; SELECT "2";`,
			want: []string{
				`SELECT "1"`,
				`SELECT "2"`,
			},
		},
		{
			name: `Simple dual quote`,
			sql:  `SELECT "1"; SELECT '2';`,
			want: []string{
				`SELECT "1"`,
				`SELECT '2'`,
			},
		},
		{
			name: `Simple dash line comment`,
			sql: `SELECT 1; -- line comment
SELECT 2;`,
			want: []string{
				`SELECT 1`,
				`-- line comment
SELECT 2`,
			},
		},
		{
			name: `Simple slash line comment`,
			sql: `SELECT 1; // line comment
SELECT 2;`,
			want: []string{
				`SELECT 1`,
				`// line comment
SELECT 2`,
			},
		},
		{
			name: `Simple multi line comment`,
			sql: `SELECT 1; /* line 
comment /*
SELECT 2`,
			want: []string{
				`SELECT 1`,
				`/* line 
comment /*
SELECT 2`,
			},
		},
		{
			name: `Semicolon in dash line comment`,
			sql: `SELECT 1 -- comment ;
FROM tble`,
			want: []string{
				`SELECT 1 -- comment ;
FROM tble`,
			},
		},
		{
			name: `Semicolon in slash line comment`,
			sql: `SELECT 1 // comment ;
FROM tble`,
			want: []string{
				`SELECT 1 // comment ;
FROM tble`,
			},
		},
		{
			name: `Semicolon in multi line comment`,
			sql: `SELECT 1 /* comment 
; */
FROM tble`,
			want: []string{
				`SELECT 1 /* comment 
; */
FROM tble`,
			},
		},
		{
			name: `Asterisks in multi line comment`,
			sql: `SELECT 1 /* comment** * **** 
; ** */
FROM tble`,
			want: []string{
				`SELECT 1 /* comment** * **** 
; ** */
FROM tble`,
			},
		},
		{
			name: `Semicolon after half dash line comment`,
			sql: `SELECT 1- -- still working ;
; SELECT 2;`,
			want: []string{
				`SELECT 1- -- still working ;`,
				`SELECT 2`,
			},
		},
		{
			name: `Semicolon after slash dash line comment`,
			sql: `SELECT 1/ // still working ;
; SELECT 2;`,
			want: []string{
				`SELECT 1/ // still working ;`,
				`SELECT 2`,
			},
		},
		{
			name: `Semicolon after half multi line comment`,
			sql:  `SELECT 1/ * /**/; SELECT 2;`,
			want: []string{
				`SELECT 1/ * /**/`,
				`SELECT 2`,
			},
		},
		{
			name: `Semicolon after unopened closing multi line comment`,
			sql:  `SELECT 1*/ /*;*/; SELECT 2;`,
			want: []string{
				`SELECT 1*/ /*;*/`,
				`SELECT 2`,
			},
		},
		{
			name: `Single quote in comment real example`,
			sql: `-- Load field definitions for (free-standing) composite types
SELECT typ.oid, att.attname, att.atttypid
FROM pg_type AS typ
JOIN pg_namespace AS ns ON (ns.oid = typ.typnamespace)
JOIN pg_class AS cls ON (cls.oid = typ.typrelid)
JOIN pg_attribute AS att ON (att.attrelid = typ.typrelid)
WHERE
(typ.typtype = 'c' AND cls.relkind='c') AND

attnum > 0 AND   -- Don't load system attributes
NOT attisdropped
ORDER BY typ.oid, att.attnum;

-- Load enum fields
SELECT pg_type.oid, enumlabel /* **/
FROM pg_enum
JOIN pg_type ON pg_type.oid=enumtypid
ORDER BY oid, enumsortorder;`,
			want: []string{
				`-- Load field definitions for (free-standing) composite types
SELECT typ.oid, att.attname, att.atttypid
FROM pg_type AS typ
JOIN pg_namespace AS ns ON (ns.oid = typ.typnamespace)
JOIN pg_class AS cls ON (cls.oid = typ.typrelid)
JOIN pg_attribute AS att ON (att.attrelid = typ.typrelid)
WHERE
(typ.typtype = 'c' AND cls.relkind='c') AND

attnum > 0 AND   -- Don't load system attributes
NOT attisdropped
ORDER BY typ.oid, att.attnum`,
				`-- Load enum fields
SELECT pg_type.oid, enumlabel /* **/
FROM pg_enum
JOIN pg_type ON pg_type.oid=enumtypid
ORDER BY oid, enumsortorder`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitQueries(tt.sql); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitQueries() = %v, want %v", spew.Sdump(got), spew.Sdump(tt.want))
			}
		})
	}
}

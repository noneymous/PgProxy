package pgproxy

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	scanUtils "github.com/siemens/GoScans/utils"
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

// TestPrettify_FallbackCleanup_PreservesFormatting verifies cleanup applies to successful and failed formatting
func TestPrettify_FallbackCleanup_PreservesFormatting(t *testing.T) {

	// Prepare unit test data for the normal path and each input-dependent fallback
	tests := []struct {
		name        string
		query       string
		wantSql     string
		wantTables  []string
		wantWarning string
	}{
		{
			name:    "empty",
			query:   "",
			wantSql: "",
		},
		{
			name:    "whitespace-only",
			query:   " \t\n\n\r ",
			wantSql: "",
		},
		{
			name:       "formatted-query-with-table",
			query:      "  select id from example_table  ",
			wantSql:    "SELECT\n  id\nFROM example_table",
			wantTables: []string{"example_table"},
		},
		{
			name:        "tokenizer-error-empty-lines",
			query:       "\n\tSELECT\n\n'unterminated\n",
			wantSql:     "SELECT\n'unterminated",
			wantWarning: "Could not tokenize query:",
		},
		{
			name:        "tokenizer-error-whitespace-normalization",
			query:       "\nSELECT    id\n\nFROM\texample_table\nWHERE name = 'unterminated\n",
			wantSql:     "SELECT  id\nFROM  example_table\nWHERE name = 'unterminated",
			wantWarning: "Could not tokenize query:",
		},
		{
			name:        "tokenizer-error-escaped-quote",
			query:       "SELECT E'\\''\n\nFROM example_table",
			wantSql:     "SELECT E'\\''\nFROM example_table",
			wantWarning: "Could not tokenize query:",
		},
		{
			name:        "parser-error-retains-tables-and-cleanup",
			query:       "\nUNSUPPORTED\n\nFROM example_table\n",
			wantSql:     "UNSUPPORTED\nFROM example_table",
			wantTables:  []string{"example_table"},
			wantWarning: "Could not parse query:",
		},
	}

	// Prepare and run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Capture real formatter diagnostics without replacing its dependencies
			var logs bytes.Buffer
			logger := scanUtils.NewTestLogger()
			logger.SetOutput(&logs)
			tables, sql := prettify(logger, test.query)

			// Verify final cleanup and table extraction on both normal and fallback paths
			if sql != test.wantSql {
				t.Errorf("prettify() SQL = '%s', want = '%s'", sql, test.wantSql)
			}
			if !reflect.DeepEqual(tables, test.wantTables) {
				t.Errorf("prettify() tables = '%v', want = '%v'", tables, test.wantTables)
			}

			// Verify failed formatting produces one warning without cascading diagnostics
			if test.wantWarning == "" {
				if logs.Len() != 0 {
					t.Errorf("prettify() logs = '%s', want = ''", logs.String())
				}
			} else if !strings.Contains(logs.String(), test.wantWarning) || strings.Count(logs.String(), "Could not ") != 1 {
				t.Errorf("prettify() logs = '%s', want = 'one %s warning'", logs.String(), test.wantWarning)
			}
		})
	}
}

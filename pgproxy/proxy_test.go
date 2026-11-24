package pgproxy

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	scanUtils "github.com/siemens/GoScans/utils"
)

// Test_splitQueries verifies the original multi-statement splitting examples
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
			name: `Semicolon after slash operator`,
			sql: `SELECT 1 // comment ;
FROM tble`,
			want: []string{
				`SELECT 1 // comment`,
				`FROM tble`,
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
				`SELECT 1/ // still working`,
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
			if got := splitQueries(tt.sql, true); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitQueries() = %v, want %v", spew.Sdump(got), spew.Sdump(tt.want))
			}
		})
	}
}

// TestSplitQueries_QuotedContent_PreservesStatementBoundaries verifies PostgreSQL literals do not hide separators
func TestSplitQueries_QuotedContent_PreservesStatementBoundaries(t *testing.T) {

	// Prepare unit test data for quoting and comments that previously confused monitoring
	tests := []struct {
		name  string
		first string
	}{
		{
			name:  "quoted-url",
			first: `SELECT 'https://example.com'`,
		},
		{
			name:  "quoted-line-comment",
			first: `SELECT 'a--b'`,
		},
		{
			name:  "quoted-block-comment",
			first: `SELECT 'a/*b'`,
		},
		{
			name:  "quoted-identifier",
			first: `SELECT 1 AS "a--b/*c//d;e"`,
		},
		{
			name:  "doubled-quotes",
			first: `SELECT 'a''--b;c' AS "a""/*b;c"`,
		},
		{
			name:  "escape-string",
			first: `SELECT E'\''`,
		},
		{
			name:  "escape-string-backslash",
			first: `SELECT e'\\'`,
		},
		{
			name:  "ordinary-string-backslash",
			first: `SELECT '\'`,
		},
		{
			name:  "dollar-quoted-string",
			first: `SELECT $$a';--/*https://example.com$$`,
		},
		{
			name:  "tagged-dollar-quoted-string",
			first: `SELECT $tag_1$a;$other$;b$tag_1$`,
		},
		{
			name:  "dollar-in-identifier",
			first: `SELECT name$tag$ FROM example`,
		},
		{
			name:  "nested-block-comment",
			first: `SELECT 1 /* outer /* inner */ ; ' */`,
		},
		{
			name:  "block-comment-closes-before-semicolon",
			first: `SELECT 1 /*;*/`,
		},
		{
			name:  "slash-operator-is-not-a-comment",
			first: `SELECT 8 // 2`,
		},
		{
			name:  "continued-escape-string",
			first: "SELECT E'a'\n'\\''",
		},
		{
			name:  "continued-escape-string-after-line-comment",
			first: "SELECT E'a' -- continuation\r\n'\\''",
		},
		{
			name:  "atomic-function-body",
			first: `CREATE FUNCTION example() RETURNS int LANGUAGE SQL BEGIN ATOMIC SELECT 1; SELECT 2; END`,
		},
		{
			name:  "atomic-procedure-with-case",
			first: `CREATE OR REPLACE PROCEDURE example() LANGUAGE SQL BEGIN ATOMIC SELECT CASE WHEN true THEN 1 ELSE 2 END; SELECT 3; END`,
		},
		{
			name:  "routine-keywords-as-column-labels",
			first: `CREATE FUNCTION example() RETURNS int LANGUAGE SQL BEGIN ATOMIC SELECT 1 AS begin; SELECT 3; END`,
		},
		{
			name:  "routine-keywords-as-case-labels",
			first: `CREATE FUNCTION example() RETURNS int LANGUAGE SQL BEGIN ATOMIC SELECT CASE WHEN true THEN 1 ELSE 2 END AS end; SELECT 3; END`,
		},
		{
			name:  "rule-action-list",
			first: `CREATE RULE example AS ON INSERT TO example_table DO ALSO (SELECT 1; SELECT 2;)`,
		},
	}

	// Prepare and run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Verify only the unquoted separator creates a new statement
			want := []string{test.first, "SELECT 2"}
			if got := splitQueries(test.first+"; SELECT 2;", true); !reflect.DeepEqual(got, want) {
				t.Errorf("splitQueries() queries = '%v', want = '%v'", got, want)
			}
		})
	}
}

// TestSplitQueries_EmptyAndCommentInput_DoesNotQueueExtraStatements verifies comments have no completion response
func TestSplitQueries_EmptyAndCommentInput_DoesNotQueueExtraStatements(t *testing.T) {

	// Prepare unit test data for empty batches and comments between or after statements
	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{
			name:  "empty",
			query: " ; \t;\r\n",
			want:  []string{},
		},
		{
			name:  "comments-only",
			query: "/* outer /* inner */ done */; -- end\r\n",
			want:  []string{},
		},
		{
			name:  "trailing-comments",
			query: "SELECT 1; /* end */; -- end",
			want:  []string{"SELECT 1"},
		},
		{
			name:  "leading-comments",
			query: "-- first\rSELECT 1; /* second */ SELECT 2",
			want:  []string{"-- first\rSELECT 1", "/* second */ SELECT 2"},
		},
		{
			name:  "unterminated-string",
			query: "SELECT 'unfinished; SELECT 2",
			want:  []string{"SELECT 'unfinished; SELECT 2"},
		},
		{
			name:  "unterminated-dollar-string",
			query: "SELECT $tag$unfinished; SELECT 2",
			want:  []string{"SELECT $tag$unfinished; SELECT 2"},
		},
		{
			name:  "all-whitespace",
			query: " \t\r\n\f\v",
			want:  []string{},
		},
		{
			name:  "comment-quote-and-delimiter-lookalikes",
			query: "-- '\"$tag$/*;\r/* -- '\"; */;",
			want:  []string{},
		},
		{
			name:  "unterminated-identifier",
			query: `SELECT "unfinished; SELECT 2`,
			want:  []string{`SELECT "unfinished; SELECT 2`},
		},
		{
			name:  "unterminated-escape-at-end",
			query: `SELECT E'unfinished\`,
			want:  []string{`SELECT E'unfinished\`},
		},
		{
			name:  "unterminated-comment-only",
			query: `/* unfinished; SELECT 2`,
			want:  []string{`/* unfinished; SELECT 2`},
		},
		{
			name:  "unterminated-nested-comment",
			query: `SELECT 1 /* outer /* inner */; SELECT 2`,
			want:  []string{`SELECT 1 /* outer /* inner */; SELECT 2`},
		},
		{
			name:  "unterminated-parenthesis",
			query: `SELECT (1; SELECT 2`,
			want:  []string{`SELECT (1; SELECT 2`},
		},
		{
			name:  "dollar-tag-case-sensitive",
			query: `SELECT $Tag$unfinished$tag$; SELECT 2`,
			want:  []string{`SELECT $Tag$unfinished$tag$; SELECT 2`},
		},
	}

	// Prepare and run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Verify monitoring matches PostgreSQL's nonempty statement sequence
			if got := splitQueries(test.query, true); !reflect.DeepEqual(got, test.want) {
				t.Errorf("splitQueries() queries = '%v', want = '%v'", got, test.want)
			}
		})
	}
}

// TestSplitQueries_LexicalCombinations_PreservesExactSql verifies combinations of quoting, comments and separators
func TestSplitQueries_LexicalCombinations_PreservesExactSql(t *testing.T) {

	// Prepare unit test data with independently varied prefixes, separators and empty trailing fragments
	prefixes := []string{"", "/* header */ ", "-- header\r\n"}
	separators := []string{";", ";\n", "; /* gap */ ", "; -- gap\r\n"}
	suffixes := []string{"", ";", "; ; ;", "; /* tail */; -- tail", ";\r\n-- tail\r\n;"}

	// Prepare and run test cases across the complete lexical expression corpus
	for i, expression := range test_splitExpressions() {
		for j, prefix := range prefixes {
			for n, separator := range separators {
				for suffixIndex, suffix := range suffixes {
					t.Run(fmt.Sprintf("expression-%02d-prefix-%d-separator-%d-suffix-%d", i, j, n, suffixIndex), func(t *testing.T) {

						// Verify neither SQL content nor the two statement boundaries change
						query := prefix + expression + separator + "SELECT 42" + suffix
						want := []string{trimEmptySyntax(prefix + expression), trimEmptySyntax(separator[1:] + "SELECT 42")}
						if got := splitQueries(query, true); !reflect.DeepEqual(got, want) {
							t.Errorf("splitQueries() queries = '%q', want = '%q'", got, want)
						}
					})
				}
			}
		}
	}
}

// TestSplitQueries_StringModes_PreservesBoundaries verifies the server's standard_conforming_strings mode is honored
func TestSplitQueries_StringModes_PreservesBoundaries(t *testing.T) {

	// Prepare unit test data for ordinary, national, escaped and bit strings in both server modes
	tests := []struct {
		name     string
		first    string
		standard bool
	}{
		{
			name:     "ordinary-standard-backslash",
			first:    `SELECT '\'`,
			standard: true,
		},
		{
			name:     "ordinary-legacy-escaped-quote",
			first:    `SELECT '\''`,
			standard: false,
		},
		{
			name:     "national-legacy-escaped-quote",
			first:    `SELECT N'\''`,
			standard: false,
		},
		{
			name:     "escaped-standard-quote",
			first:    `SELECT E'\''`,
			standard: true,
		},
		{
			name:     "escaped-legacy-quote",
			first:    `SELECT E'\''`,
			standard: false,
		},
		{
			name:     "legacy-bit-string-backslash-is-not-an-escape",
			first:    `SELECT B'\'`,
			standard: false,
		},
		{
			name:     "legacy-hex-string-backslash-is-not-an-escape",
			first:    `SELECT X'\'`,
			standard: false,
		},
	}

	// Prepare and run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Verify mode-dependent escaping never consumes the next statement
			want := []string{test.first, "SELECT 42"}
			if got := splitQueries(test.first+"; SELECT 42;", test.standard); !reflect.DeepEqual(got, want) {
				t.Errorf("splitQueries() queries = '%q', want = '%q'", got, want)
			}
		})
	}
}

// TestSplitQueries_RepeatedDelimiters_PreservesBoundaries verifies odd and even escaping and deep nesting
func TestSplitQueries_RepeatedDelimiters_PreservesBoundaries(t *testing.T) {

	// Prepare and run test cases beyond the one-character boundary examples
	for i := 0; i <= 64; i++ {
		t.Run(fmt.Sprintf("depth-%02d", i), func(t *testing.T) {

			// Build valid E strings whose closing quote follows an odd or even backslash run
			escaped := "SELECT E'" + strings.Repeat("\\", i) + "'"
			if i%2 == 1 {
				escaped += "'"
			}

			// Verify each independently varied delimiter sequence leaves the final SELECT outside it
			queries := []string{
				escaped,
				"SELECT '" + strings.Repeat("''", i) + ";--/*'",
				"SELECT 1 AS \"" + strings.Repeat("\"\"", i) + ";--/*\"",
				"SELECT 1 " + strings.Repeat("/*", i) + strings.Repeat("*/", i),
				"SELECT $tag" + strings.Repeat("x", i) + "$;--/*$tag" + strings.Repeat("x", i) + "$",
			}
			for _, query := range queries {
				want := []string{trimEmptySyntax(query), "SELECT 42"}
				if got := splitQueries(query+"; SELECT 42", true); !reflect.DeepEqual(got, want) {
					t.Errorf("splitQueries() queries = '%q', want = '%q'", got, want)
				}
			}
		})
	}
}

// TestSplitQueries_LargeInput_PreservesContent verifies long literals are not truncated or split at internal markers
func TestSplitQueries_LargeInput_PreservesContent(t *testing.T) {

	// Prepare unit test data larger than typical query buffers
	query := "SELECT '" + strings.Repeat("x;--/*//''", 128*1024) + "'"
	want := []string{query, "SELECT 42"}

	// Verify byte-exact content preservation across the large input
	if got := splitQueries(query+"; SELECT 42", true); !reflect.DeepEqual(got, want) {
		t.Errorf("splitQueries() statements = '%d', want = '2 with original content'", len(got))
	}
}

// FuzzSplitQueries_PreservesInput verifies arbitrary bytes cannot panic, overlap or alter extracted SQL
func FuzzSplitQueries_PreservesInput(f *testing.F) {

	// Seed real lexical variations together with malformed boundary input
	for _, query := range append(test_splitExpressions(), "", ";;;", "SELECT '", "SELECT E'\\", "SELECT $tag$", "/* /*", "SELECT (1;", "\x00\xff; SELECT 2") {
		f.Add(query, true)
		f.Add(query, false)
	}
	for _, query := range []string{
		`CREATE FUNCTION example() RETURNS int LANGUAGE SQL BEGIN ATOMIC SELECT 1 AS begin; SELECT CASE WHEN true THEN 2 ELSE 3 END AS end; END; SELECT 42`,
		`CREATE RULE example AS ON INSERT TO example_table DO ALSO (SELECT 1; SELECT 2;); SELECT 42`,
		`CREATE OR REPLACE PROCEDURE example() LANGUAGE SQL BEGIN ATOMIC SELECT 1; END; SELECT 42`,
	} {
		f.Add(query, true)
	}

	// Verify ordered input preservation and stable boundaries on independently extracted statements
	f.Fuzz(func(t *testing.T, query string, standard bool) {
		position := 0
		for _, part := range splitQueries(query, standard) {
			index := strings.Index(query[position:], part)
			if part == "" || index < 0 {
				t.Fatalf("splitQueries() part = '%q', want = 'nonempty ordered input substring'", part)
			}
			position += index + len(part)
			if got := splitQueries(part, standard); !reflect.DeepEqual(got, []string{part}) {
				t.Errorf("splitQueries() repeated split = '%q', want = '%q'", got, []string{part})
			}
		}
	})
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
			name:    "explain-update-segment-context",
			query:   `EXPLAIN UPDATE example_table SET id = 1`,
			wantSql: "EXPLAIN\nUPDATE example_table\nSET id = 1",
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

// test_splitExpressions returns fresh PostgreSQL expressions shared by unit and real-server checks
func test_splitExpressions() []string {

	// Cover literal families, Unicode, adjacent syntax, comments and SQL commands without changing shared state
	return []string{
		`SELECT 1`,
		`SELECT 'https://example.com/a;b--c/*d*/'`,
		`SELECT '' AS """;--/*"`,
		`SELECT 'a''b;--/*'`,
		`SELECT E'\''`,
		`SELECT e'a\\b\';--/*'`,
		`SELECT '\'`,
		"SELECT E'a'\n'\\''",
		"SELECT E'a' -- continuation\r\n'\\''",
		"SELECT 'a'\r'b;--/*'",
		`SELECT N'a;--/*'`,
		`SELECT B'0101'`,
		`SELECT X'Cafe'`,
		`SELECT U&'d\0061t\+000061'`,
		`SELECT U&'a!0062;c' UESCAPE '!'`,
		`SELECT 1 AS U&"d\0061t\+000061"`,
		`SELECT $$a';--/*$$`,
		`SELECT $Tag_1$a;$tag_1$;b$Tag_1$`,
		`SELECT $_$a;"--/*$_$`,
		`SELECT $日本語$a;--/*$日本語$`,
		`SELECT 'Grüße 日本語 😀;--/*'`,
		`SELECT '{"url":"https://example.com;a"}'::jsonb`,
		`SELECT ARRAY['a;b', E'c\nd']`,
		`SELECT ((1)) /* outer /* inner ; ' */ done */`,
		"SELECT 1 -- ; ' /* ignored\r\n",
		`WITH example AS (SELECT ';--/*' AS value) SELECT value FROM example`,
		`SELECT CASE WHEN true THEN ';' ELSE '--' END`,
		`SHOW transaction_read_only`,
	}
}

// Copyright 2012, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlparser

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/youtube/vitess/go/sqltypes"
)

const eofChar = 0x100

// Tokenizer is the struct used to generate SQL
// tokens for the parser.
type Tokenizer struct {
	InStream      *strings.Reader
	AllowComments bool
	ForceEOF      bool
	lastChar      uint16
	Position      int
	lastToken     []byte
	LastError     string
	posVarIndex   int
	ParseTree     Statement
	nesting       int
}

// NewStringTokenizer creates a new Tokenizer for the
// sql string.
func NewStringTokenizer(sql string) *Tokenizer {
	return &Tokenizer{InStream: strings.NewReader(sql)}
}

// keywords is a map of mysql keywords that fall into two categories:
// 1) keywords considered reserved by MySQL
// 2) keywords for us to handle specially in sql.y
//
// Those marked as UNUSED are likely reserved keywords. We add them here so that
// when rewriting queries we can properly backtick quote them so they don't cause issues
//
// NOTE: If you add new keywords, add them also to the reserved_keywords or
// non_reserved_keywords grammar in sql.y -- this will allow the keyword to be used
// in identifiers. See the docs for each grammar to determine which one to put it into.
var keywords = map[string]int{
	"accessible":          UNUSED,
	"add":                 UNUSED,
	"against":             AGAINST,
	"all":                 ALL,
	"alter":               ALTER,
	"analyze":             ANALYZE,
	"and":                 AND,
	"as":                  AS,
	"asc":                 ASC,
	"asensitive":          UNUSED,
	"before":              UNUSED,
	"between":             BETWEEN,
	"bigint":              UNUSED,
	"binary":              BINARY,
	"blob":                UNUSED,
	"boolean":             BOOLEAN,
	"both":                UNUSED,
	"by":                  BY,
	"call":                UNUSED,
	"cascade":             UNUSED,
	"case":                CASE,
	"cast":                CAST,
	"change":              UNUSED,
	"character":           CHARACTER,
	"check":               UNUSED,
	"collate":             COLLATE,
	"column":              UNUSED,
	"condition":           UNUSED,
	"constraint":          UNUSED,
	"continue":            UNUSED,
	"convert":             CONVERT,
	"create":              CREATE,
	"cross":               CROSS,
	"current_date":        CURRENT_DATE,
	"current_time":        CURRENT_TIME,
	"current_timestamp":   CURRENT_TIMESTAMP,
	"current_user":        UNUSED,
	"cursor":              UNUSED,
	"database":            DATABASE,
	"databases":           DATABASES,
	"day_hour":            UNUSED,
	"day_microsecond":     UNUSED,
	"day_minute":          UNUSED,
	"day_second":          UNUSED,
	"date":                DATE,
	"dec":                 UNUSED,
	"declare":             UNUSED,
	"default":             DEFAULT,
	"delayed":             UNUSED,
	"delete":              DELETE,
	"desc":                DESC,
	"describe":            DESCRIBE,
	"deterministic":       UNUSED,
	"distinct":            DISTINCT,
	"distinctrow":         UNUSED,
	"div":                 DIV,
	"double":              UNUSED,
	"drop":                DROP,
	"duplicate":           DUPLICATE,
	"each":                UNUSED,
	"else":                ELSE,
	"elseif":              UNUSED,
	"enclosed":            UNUSED,
	"end":                 END,
	"escape":              ESCAPE,
	"escaped":             UNUSED,
	"exists":              EXISTS,
	"exit":                UNUSED,
	"explain":             EXPLAIN,
	"expansion":           EXPANSION,
	"false":               FALSE,
	"fetch":               UNUSED,
	"float":               UNUSED,
	"float4":              UNUSED,
	"float8":              UNUSED,
	"for":                 FOR,
	"force":               FORCE,
	"foreign":             UNUSED,
	"from":                FROM,
	"fulltext":            UNUSED,
	"generated":           UNUSED,
	"get":                 UNUSED,
	"grant":               UNUSED,
	"group":               GROUP,
	"group_concat":        GROUP_CONCAT,
	"having":              HAVING,
	"high_priority":       UNUSED,
	"hour_microsecond":    UNUSED,
	"hour_minute":         UNUSED,
	"hour_second":         UNUSED,
	"if":                  IF,
	"ignore":              IGNORE,
	"in":                  IN,
	"index":               INDEX,
	"infile":              UNUSED,
	"inout":               UNUSED,
	"inner":               INNER,
	"insensitive":         UNUSED,
	"insert":              INSERT,
	"int":                 UNUSED,
	"int1":                UNUSED,
	"int2":                UNUSED,
	"int3":                UNUSED,
	"int4":                UNUSED,
	"int8":                UNUSED,
	"integer":             INTEGER,
	"interval":            INTERVAL,
	"into":                INTO,
	"io_after_gtids":      UNUSED,
	"is":                  IS,
	"iterate":             UNUSED,
	"join":                JOIN,
	"key":                 KEY,
	"keys":                UNUSED,
	"kill":                UNUSED,
	"language":            LANGUAGE,
	"last_insert_id":      LAST_INSERT_ID,
	"leading":             UNUSED,
	"leave":               UNUSED,
	"left":                LEFT,
	"like":                LIKE,
	"limit":               LIMIT,
	"linear":              UNUSED,
	"lines":               UNUSED,
	"load":                UNUSED,
	"localtime":           LOCALTIME,
	"localtimestamp":      LOCALTIMESTAMP,
	"lock":                LOCK,
	"long":                UNUSED,
	"longblob":            UNUSED,
	"longtext":            UNUSED,
	"loop":                UNUSED,
	"low_priority":        UNUSED,
	"master_bind":         UNUSED,
	"match":               MATCH,
	"maxvalue":            UNUSED,
	"mediumblob":          UNUSED,
	"mediumint":           UNUSED,
	"mediumtext":          UNUSED,
	"middleint":           UNUSED,
	"minute_microsecond":  UNUSED,
	"minute_second":       UNUSED,
	"mod":                 MOD,
	"mode":                MODE,
	"modifies":            UNUSED,
	"natural":             NATURAL,
	"next":                NEXT,
	"not":                 NOT,
	"no_write_to_binlog":  UNUSED,
	"null":                NULL,
	"numeric":             UNUSED,
	"offset":              OFFSET,
	"on":                  ON,
	"optimize":            OPTIMIZE,
	"optimizer_costs":     UNUSED,
	"option":              UNUSED,
	"optionally":          UNUSED,
	"or":                  OR,
	"order":               ORDER,
	"out":                 UNUSED,
	"outer":               OUTER,
	"outfile":             UNUSED,
	"partition":           UNUSED,
	"precision":           UNUSED,
	"primary":             UNUSED,
	"procedure":           UNUSED,
	"query":               QUERY,
	"range":               UNUSED,
	"read":                UNUSED,
	"reads":               UNUSED,
	"read_write":          UNUSED,
	"real":                UNUSED,
	"references":          UNUSED,
	"regexp":              REGEXP,
	"release":             UNUSED,
	"rename":              RENAME,
	"repair":              REPAIR,
	"repeat":              UNUSED,
	"replace":             REPLACE,
	"require":             UNUSED,
	"resignal":            UNUSED,
	"restrict":            UNUSED,
	"return":              UNUSED,
	"revoke":              UNUSED,
	"right":               RIGHT,
	"rlike":               REGEXP,
	"schema":              UNUSED,
	"schemas":             UNUSED,
	"second_microsecond":  UNUSED,
	"select":              SELECT,
	"sensitive":           UNUSED,
	"separator":           SEPARATOR,
	"set":                 SET,
	"share":               SHARE,
	"show":                SHOW,
	"signal":              UNUSED,
	"smallint":            UNUSED,
	"spatial":             UNUSED,
	"specific":            UNUSED,
	"sql":                 UNUSED,
	"sqlexception":        UNUSED,
	"sqlstate":            UNUSED,
	"sqlwarning":          UNUSED,
	"sql_big_result":      UNUSED,
	"sql_cache":           SQL_CACHE,
	"sql_calc_found_rows": UNUSED,
	"sql_no_cache":        SQL_NO_CACHE,
	"sql_small_result":    UNUSED,
	"ssl":                 UNUSED,
	"starting":            UNUSED,
	"stored":              UNUSED,
	"straight_join":       STRAIGHT_JOIN,
	"table":               TABLE,
	"tables":              TABLES,
	"terminated":          UNUSED,
	"then":                THEN,
	"tinyblob":            UNUSED,
	"tinyint":             UNUSED,
	"tinytext":            UNUSED,
	"to":                  TO,
	"trailing":            UNUSED,
	"trigger":             UNUSED,
	"true":                TRUE,
	"truncate":            TRUNCATE,
	"undo":                UNUSED,
	"union":               UNION,
	"unique":              UNIQUE,
	"unlock":              UNUSED,
	"update":              UPDATE,
	"usage":               UNUSED,
	"use":                 USE,
	"using":               USING,
	"utc_date":            UTC_DATE,
	"utc_time":            UTC_TIME,
	"utc_timestamp":       UTC_TIMESTAMP,
	"values":              VALUES,
	"varbinary":           UNUSED,
	"varchar":             UNUSED,
	"varcharacter":        UNUSED,
	"varying":             UNUSED,
	"virtual":             UNUSED,
	"view":                VIEW,
	"vitess_keyspaces":    VITESS_KEYSPACES,
	"vitess_shards":       VITESS_SHARDS,
	"vschema_tables":      VSCHEMA_TABLES,
	"when":                WHEN,
	"where":               WHERE,
	"while":               UNUSED,
	"with":                WITH,
	"write":               UNUSED,
	"xor":                 UNUSED,
	"year_month":          UNUSED,
	"zerofill":            UNUSED,
}

// Lex returns the next token form the Tokenizer.
// This function is used by go yacc.
func (tkn *Tokenizer) Lex(lval *yySymType) int {
	typ, val := tkn.Scan()
	for typ == COMMENT {
		if tkn.AllowComments {
			break
		}
		typ, val = tkn.Scan()
	}
	lval.bytes = val
	tkn.lastToken = val
	return typ
}

// Error is called by go yacc if there's a parsing error.
func (tkn *Tokenizer) Error(err string) {
	buf := &bytes.Buffer{}
	if tkn.lastToken != nil {
		fmt.Fprintf(buf, "%s at position %v near '%s'", err, tkn.Position, tkn.lastToken)
	} else {
		fmt.Fprintf(buf, "%s at position %v", err, tkn.Position)
	}
	tkn.LastError = buf.String()
}

// Scan scans the tokenizer for the next token and returns
// the token type and an optional value.
func (tkn *Tokenizer) Scan() (int, []byte) {
	if tkn.ForceEOF {
		return 0, nil
	}

	if tkn.lastChar == 0 {
		tkn.next()
	}
	tkn.skipBlank()
	switch ch := tkn.lastChar; {
	case isLetter(ch):
		tkn.next()
		if ch == 'X' || ch == 'x' {
			if tkn.lastChar == '\'' {
				tkn.next()
				return tkn.scanHex()
			}
		}
		return tkn.scanIdentifier(byte(ch))
	case isDigit(ch):
		return tkn.scanNumber(false)
	case ch == ':':
		return tkn.scanBindVar()
	default:
		tkn.next()
		switch ch {
		case eofChar:
			return 0, nil
		case '=', ',', ';', '(', ')', '+', '*', '%', '^', '~':
			return int(ch), nil
		case '&':
			if tkn.lastChar == '&' {
				tkn.next()
				return AND, nil
			}
			return int(ch), nil
		case '|':
			if tkn.lastChar == '|' {
				tkn.next()
				return OR, nil
			}
			return int(ch), nil
		case '?':
			tkn.posVarIndex++
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, ":v%d", tkn.posVarIndex)
			return VALUE_ARG, buf.Bytes()
		case '.':
			if isDigit(tkn.lastChar) {
				return tkn.scanNumber(true)
			}
			return int(ch), nil
		case '/':
			switch tkn.lastChar {
			case '/':
				tkn.next()
				return tkn.scanCommentType1("//")
			case '*':
				tkn.next()
				return tkn.scanCommentType2()
			default:
				return int(ch), nil
			}
		case '#':
			tkn.next()
			return tkn.scanCommentType1("#")
		case '-':
			switch tkn.lastChar {
			case '-':
				tkn.next()
				return tkn.scanCommentType1("--")
			case '>':
				tkn.next()
				if tkn.lastChar == '>' {
					tkn.next()
					return JSON_UNQUOTE_EXTRACT_OP, nil
				}
				return JSON_EXTRACT_OP, nil
			}
			return int(ch), nil
		case '<':
			switch tkn.lastChar {
			case '>':
				tkn.next()
				return NE, nil
			case '<':
				tkn.next()
				return SHIFT_LEFT, nil
			case '=':
				tkn.next()
				switch tkn.lastChar {
				case '>':
					tkn.next()
					return NULL_SAFE_EQUAL, nil
				default:
					return LE, nil
				}
			default:
				return int(ch), nil
			}
		case '>':
			switch tkn.lastChar {
			case '=':
				tkn.next()
				return GE, nil
			case '>':
				tkn.next()
				return SHIFT_RIGHT, nil
			default:
				return int(ch), nil
			}
		case '!':
			if tkn.lastChar == '=' {
				tkn.next()
				return NE, nil
			}
			return int(ch), nil
		case '\'', '"':
			return tkn.scanString(ch, STRING)
		case '`':
			return tkn.scanLiteralIdentifier()
		default:
			return LEX_ERROR, []byte{byte(ch)}
		}
	}
}

func (tkn *Tokenizer) skipBlank() {
	ch := tkn.lastChar
	for ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' {
		tkn.next()
		ch = tkn.lastChar
	}
}

func (tkn *Tokenizer) scanIdentifier(firstByte byte) (int, []byte) {
	buffer := &bytes.Buffer{}
	buffer.WriteByte(firstByte)
	for isLetter(tkn.lastChar) || isDigit(tkn.lastChar) {
		buffer.WriteByte(byte(tkn.lastChar))
		tkn.next()
	}
	lowered := bytes.ToLower(buffer.Bytes())
	loweredStr := string(lowered)
	if keywordID, found := keywords[loweredStr]; found {
		return keywordID, lowered
	}
	// dual must always be case-insensitive
	if loweredStr == "dual" {
		return ID, lowered
	}
	return ID, buffer.Bytes()
}

func (tkn *Tokenizer) scanHex() (int, []byte) {
	buffer := &bytes.Buffer{}
	tkn.scanMantissa(16, buffer)
	if tkn.lastChar != '\'' {
		return LEX_ERROR, buffer.Bytes()
	}
	tkn.next()
	if buffer.Len()%2 != 0 {
		return LEX_ERROR, buffer.Bytes()
	}
	return HEX, buffer.Bytes()
}

func (tkn *Tokenizer) scanLiteralIdentifier() (int, []byte) {
	buffer := &bytes.Buffer{}
	backTickSeen := false
	for {
		if backTickSeen {
			if tkn.lastChar != '`' {
				break
			}
			backTickSeen = false
			buffer.WriteByte('`')
			tkn.next()
			continue
		}
		// The previous char was not a backtick.
		switch tkn.lastChar {
		case '`':
			backTickSeen = true
		case eofChar:
			// Premature EOF.
			return LEX_ERROR, buffer.Bytes()
		default:
			buffer.WriteByte(byte(tkn.lastChar))
		}
		tkn.next()
	}
	if buffer.Len() == 0 {
		return LEX_ERROR, buffer.Bytes()
	}
	return ID, buffer.Bytes()
}

func (tkn *Tokenizer) scanBindVar() (int, []byte) {
	buffer := &bytes.Buffer{}
	buffer.WriteByte(byte(tkn.lastChar))
	token := VALUE_ARG
	tkn.next()
	if tkn.lastChar == ':' {
		token = LIST_ARG
		buffer.WriteByte(byte(tkn.lastChar))
		tkn.next()
	}
	if !isLetter(tkn.lastChar) {
		return LEX_ERROR, buffer.Bytes()
	}
	for isLetter(tkn.lastChar) || isDigit(tkn.lastChar) || tkn.lastChar == '.' {
		buffer.WriteByte(byte(tkn.lastChar))
		tkn.next()
	}
	return token, buffer.Bytes()
}

func (tkn *Tokenizer) scanMantissa(base int, buffer *bytes.Buffer) {
	for digitVal(tkn.lastChar) < base {
		tkn.consumeNext(buffer)
	}
}

func (tkn *Tokenizer) scanNumber(seenDecimalPoint bool) (int, []byte) {
	token := INTEGRAL
	buffer := &bytes.Buffer{}
	if seenDecimalPoint {
		token = FLOAT
		buffer.WriteByte('.')
		tkn.scanMantissa(10, buffer)
		goto exponent
	}

	// 0x construct.
	if tkn.lastChar == '0' {
		tkn.consumeNext(buffer)
		if tkn.lastChar == 'x' || tkn.lastChar == 'X' {
			token = HEXNUM
			tkn.consumeNext(buffer)
			tkn.scanMantissa(16, buffer)
			goto exit
		}
	}

	tkn.scanMantissa(10, buffer)

	if tkn.lastChar == '.' {
		token = FLOAT
		tkn.consumeNext(buffer)
		tkn.scanMantissa(10, buffer)
	}

exponent:
	if tkn.lastChar == 'e' || tkn.lastChar == 'E' {
		token = FLOAT
		tkn.consumeNext(buffer)
		if tkn.lastChar == '+' || tkn.lastChar == '-' {
			tkn.consumeNext(buffer)
		}
		tkn.scanMantissa(10, buffer)
	}

exit:
	// A letter cannot immediately follow a number.
	if isLetter(tkn.lastChar) {
		return LEX_ERROR, buffer.Bytes()
	}

	return token, buffer.Bytes()
}

func (tkn *Tokenizer) scanString(delim uint16, typ int) (int, []byte) {
	buffer := &bytes.Buffer{}
	for {
		ch := tkn.lastChar
		tkn.next()
		if ch == delim {
			if tkn.lastChar == delim {
				tkn.next()
			} else {
				break
			}
		} else if ch == '\\' {
			if tkn.lastChar == eofChar {
				return LEX_ERROR, buffer.Bytes()
			}
			if decodedChar := sqltypes.SQLDecodeMap[byte(tkn.lastChar)]; decodedChar == sqltypes.DontEscape {
				ch = tkn.lastChar
			} else {
				ch = uint16(decodedChar)
			}
			tkn.next()
		}
		if ch == eofChar {
			return LEX_ERROR, buffer.Bytes()
		}
		buffer.WriteByte(byte(ch))
	}
	return typ, buffer.Bytes()
}

func (tkn *Tokenizer) scanCommentType1(prefix string) (int, []byte) {
	buffer := &bytes.Buffer{}
	buffer.WriteString(prefix)
	for tkn.lastChar != eofChar {
		if tkn.lastChar == '\n' {
			tkn.consumeNext(buffer)
			break
		}
		tkn.consumeNext(buffer)
	}
	return COMMENT, buffer.Bytes()
}

func (tkn *Tokenizer) scanCommentType2() (int, []byte) {
	buffer := &bytes.Buffer{}
	buffer.WriteString("/*")
	for {
		if tkn.lastChar == '*' {
			tkn.consumeNext(buffer)
			if tkn.lastChar == '/' {
				tkn.consumeNext(buffer)
				break
			}
			continue
		}
		if tkn.lastChar == eofChar {
			return LEX_ERROR, buffer.Bytes()
		}
		tkn.consumeNext(buffer)
	}
	return COMMENT, buffer.Bytes()
}

func (tkn *Tokenizer) consumeNext(buffer *bytes.Buffer) {
	if tkn.lastChar == eofChar {
		// This should never happen.
		panic("unexpected EOF")
	}
	buffer.WriteByte(byte(tkn.lastChar))
	tkn.next()
}

func (tkn *Tokenizer) next() {
	if ch, err := tkn.InStream.ReadByte(); err != nil {
		// Only EOF is possible.
		tkn.lastChar = eofChar
	} else {
		tkn.lastChar = uint16(ch)
	}
	tkn.Position++
}

func isLetter(ch uint16) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_' || ch == '@'
}

func digitVal(ch uint16) int {
	switch {
	case '0' <= ch && ch <= '9':
		return int(ch) - '0'
	case 'a' <= ch && ch <= 'f':
		return int(ch) - 'a' + 10
	case 'A' <= ch && ch <= 'F':
		return int(ch) - 'A' + 10
	}
	return 16 // larger than any legal digit val
}

func isDigit(ch uint16) bool {
	return '0' <= ch && ch <= '9'
}

package lo

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/samber/lo/internal/rand"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	LowerCaseLettersCharset = []rune("abcdefghijklmnopqrstuvwxyz")
	UpperCaseLettersCharset = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	LettersCharset          = append(LowerCaseLettersCharset, UpperCaseLettersCharset...)
	NumbersCharset          = []rune("0123456789")
	AlphanumericCharset     = append(LettersCharset, NumbersCharset...)
	SpecialCharset          = []rune("!@#$%^&*()_+-=[]{}|;':\",./<>?")
	AllCharset              = append(AlphanumericCharset, SpecialCharset...)

	// bearer:disable go_lang_permissive_regex_validation
	splitWordReg = regexp.MustCompile(`([a-z])([A-Z0-9])|([a-zA-Z])([0-9])|([0-9])([a-zA-Z])|([A-Z])([A-Z])([a-z])`)
	// bearer:disable go_lang_permissive_regex_validation
	splitNumberLetterReg = regexp.MustCompile(`([0-9])([a-zA-Z])`)
)

// RandomString return a random string.
// Play: https://go.dev/play/p/rRseOQVVum4
func RandomString(size int, charset []rune) string {
	if size <= 0 {
		panic("lo.RandomString: Size parameter must be greater than 0")
	}
	if len(charset) <= 0 {
		panic("lo.RandomString: Charset parameter must not be empty")
	}

	b := make([]rune, size)
	possibleCharactersCount := len(charset)
	for i := range b {
		b[i] = charset[rand.IntN(possibleCharactersCount)]
	}
	return string(b)
}

// Substring return part of a string.
// Play: https://go.dev/play/p/TQlxQi82Lu1
func Substring[T ~string](str T, offset int, length uint) T {
	rs := []rune(str)
	size := len(rs)

	if offset < 0 {
		offset = size + offset
		if offset < 0 {
			offset = 0
		}
	}

	if offset >= size {
		return Empty[T]()
	}

	if length > uint(size)-uint(offset) {
		length = uint(size - offset)
	}

	return T(strings.Replace(string(rs[offset:offset+int(length)]), "\x00", "", -1))
}

// ChunkString returns an array of strings split into groups the length of size. If array can't be split evenly,
// the final chunk will be the remaining elements.
// Play: https://go.dev/play/p/__FLTuJVz54
func ChunkString[T ~string](str T, size int) []T {
	if size <= 0 {
		panic("lo.ChunkString: Size parameter must be greater than 0")
	}

	if len(str) == 0 {
		return []T{""}
	}

	if size >= len(str) {
		return []T{str}
	}

	var chunks []T = make([]T, 0, ((len(str)-1)/size)+1)
	currentLen := 0
	currentStart := 0
	for i := range str {
		if currentLen == size {
			chunks = append(chunks, str[currentStart:i])
			currentLen = 0
			currentStart = i
		}
		currentLen++
	}
	chunks = append(chunks, str[currentStart:])
	return chunks
}

// RuneLength is an alias to utf8.RuneCountInString which returns the number of runes in string.
// Play: https://go.dev/play/p/tuhgW_lWY8l
func RuneLength(str string) int {
	return utf8.RuneCountInString(str)
}

// PascalCase converts string to pascal case.
func PascalCase(str string) string {
	items := Words(str)
	for i := range items {
		items[i] = Capitalize(items[i])
	}
	return strings.Join(items, "")
}

// CamelCase converts string to camel case.
func CamelCase(str string) string {
	items := Words(str)
	for i, item := range items {
		item = strings.ToLower(item)
		if i > 0 {
			item = Capitalize(item)
		}
		items[i] = item
	}
	return strings.Join(items, "")
}

// KebabCase converts string to kebab case.
func KebabCase(str string) string {
	items := Words(str)
	for i := range items {
		items[i] = strings.ToLower(items[i])
	}
	return strings.Join(items, "-")
}

// SnakeCase converts string to snake case.
func SnakeCase(str string) string {
	items := Words(str)
	for i := range items {
		items[i] = strings.ToLower(items[i])
	}
	return strings.Join(items, "_")
}

// Words splits string into an array of its words.
func Words(str string) []string {
	str = splitWordReg.ReplaceAllString(str, `$1$3$5$7 $2$4$6$8$9`)
	// example: Int8Value => Int 8Value => Int 8 Value
	str = splitNumberLetterReg.ReplaceAllString(str, "$1 $2")
	var result strings.Builder
	for _, r := range str {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			result.WriteRune(r)
		} else {
			result.WriteRune(' ')
		}
	}
	return strings.Fields(result.String())
}

// Capitalize converts the first character of string to upper case and the remaining to lower case.
func Capitalize(str string) string {
	return cases.Title(language.English).String(str)
}

// Elipse truncates a string to a specified length and appends an ellipsis if truncated.
func Elipse(str string, length int) string {
	if len(str) > length {
		if len(str) < 3 || length < 3 {
			return "..."
		}
		return str[0:length-3] + "..."
	}

	return str
}

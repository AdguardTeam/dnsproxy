package sprig

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// dfault checks whether `given` is set, and returns default if not set.
//
// This returns `d` if `given` appears not to be set, and `given` otherwise.
//
// For numeric types 0 is unset.
// For strings, maps, arrays, and slices, len() = 0 is considered unset.
// For bool, false is unset.
// Structs are never considered unset.
//
// For everything else, including pointers, a nil value is unset.
func dfault(d any, given ...any) any {

	if empty(given) || empty(given[0]) {
		return d
	}
	return given[0]
}

// empty returns true if the given value has the zero value for its type.
func empty(given any) bool {
	g := reflect.ValueOf(given)
	if !g.IsValid() {
		return true
	}

	// Basically adapted from text/template.isTrue
	switch g.Kind() {
	default:
		return g.IsNil()
	case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
		return g.Len() == 0
	case reflect.Bool:
		return !g.Bool()
	case reflect.Complex64, reflect.Complex128:
		return g.Complex() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return g.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return g.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return g.Float() == 0
	case reflect.Struct:
		return false
	}
}

// coalesce returns the first non-empty value.
func coalesce(v ...any) any {
	for _, val := range v {
		if !empty(val) {
			return val
		}
	}
	return nil
}

// all returns true if empty(x) is false for all values x in the list.
// If the list is empty, return true.
func all(v ...any) bool {
	for _, val := range v {
		if empty(val) {
			return false
		}
	}
	return true
}

// any returns true if empty(x) is false for any x in the list.
// If the list is empty, return false.
func any(v ...any) bool {
	for _, val := range v {
		if !empty(val) {
			return true
		}
	}
	return false
}

// fromJson decodes JSON into a structured value, ignoring errors.
func fromJson(v string) any {
	output, _ := mustFromJson(v)
	return output
}

// mustFromJson decodes JSON into a structured value, returning errors.
func mustFromJson(v string) (any, error) {
	var output any
	err := json.Unmarshal([]byte(v), &output)
	return output, err
}

// toJson encodes an item into a JSON string
func toJson(v any) string {
	output, _ := json.Marshal(v)
	return string(output)
}

func mustToJson(v any) (string, error) {
	output, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// toPrettyJson encodes an item into a pretty (indented) JSON string
func toPrettyJson(v any) string {
	output, _ := json.MarshalIndent(v, "", "  ")
	return string(output)
}

func mustToPrettyJson(v any) (string, error) {
	output, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// toRawJson encodes an item into a JSON string with no escaping of HTML characters.
func toRawJson(v any) string {
	output, err := mustToRawJson(v)
	if err != nil {
		panic(err)
	}
	return string(output)
}

// mustToRawJson encodes an item into a JSON string with no escaping of HTML characters.
func mustToRawJson(v any) (string, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(&v)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// ternary returns the first value if the last value is true, otherwise returns the second value.
func ternary(vt any, vf any, v bool) any {
	if v {
		return vt
	}

	return vf
}

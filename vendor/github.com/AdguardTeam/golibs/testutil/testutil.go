// Package testutil contains utilities for common testing patterns.
package testutil

import (
	"encoding"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssertErrorMsg asserts that the error is not nil and that its message is
// equal to msg.  If msg is an empty string, AssertErrorMsg asserts that the
// error is nil instead.
func AssertErrorMsg(t testing.TB, msg string, err error) (ok bool) {
	t.Helper()

	if msg == "" {
		return assert.NoError(t, err)
	}

	require.Error(t, err)

	return assert.Equal(t, msg, err.Error())
}

// stringCodecChecker is used in AssertMarshalText and AssertUnmarshalText to
// check against encoding and decoding corner cases.
type stringCodecChecker struct {
	PtrMap map[string]*string `json:"ptr_map"`
	Map    map[string]string  `json:"map"`

	PtrValue *string `json:"ptr_value"`
	Value    string  `json:"value"`

	PtrArray [1]*string `json:"ptr_array"`
	Array    [1]string  `json:"array"`

	PtrSlice []*string `json:"ptr_slice"`
	Slice    []string  `json:"slice"`
}

// newStringCodecChecker returns a codecChecker instance where all fields are
// set to s or pointer to s.
func newStringCodecChecker(s string) (c *stringCodecChecker) {
	return &stringCodecChecker{
		PtrMap: map[string]*string{"1": &s},
		Map:    map[string]string{"1": s},

		PtrValue: &s,
		Value:    s,

		PtrArray: [1]*string{&s},
		Array:    [1]string{s},

		PtrSlice: []*string{&s},
		Slice:    []string{s},
	}
}

// newGenericCodecChecker constructs a pointer to value of a type similar to the
// following:
//
//	type checker struct {
//	    PtrMap   map[string]*T `json:"ptr_map"`
//	    Map      map[string]T  `json:"map"`
//
//	    PtrValue *T            `json:"ptr_value"`
//	    Value    T             `json:"value"`
//
//	    PtrArray [1]*T         `json:"ptr_array"`
//	    Array    [1]T          `json:"array"`
//
//	    PtrSlice []*T          `json:"ptr_slice"`
//	    Slice    []T           `json:"slice"`
//	}
//
// where T is the type v points to.  The slice and pointer fields are properly
// initialized.
//
// TODO(a.garipov): Redo this with type parameters in Go 1.18.
func newGenericCodecChecker(v any) (checkerVal reflect.Value) {
	strTyp := reflect.TypeOf("")

	ptrTyp := reflect.TypeOf(v)
	ptrMapTyp := reflect.MapOf(strTyp, ptrTyp)
	ptrSliceTyp := reflect.SliceOf(ptrTyp)
	ptrArrayTyp := reflect.ArrayOf(1, ptrTyp)

	typ := ptrTyp.Elem()
	mapTyp := reflect.MapOf(strTyp, typ)
	sliceTyp := reflect.SliceOf(typ)
	arrayTyp := reflect.ArrayOf(1, typ)

	checkerTyp := reflect.StructOf([]reflect.StructField{{
		Name: "PtrMap",
		Type: ptrMapTyp,
		Tag:  reflect.StructTag(`json:"ptr_map"`),
	}, {
		Name: "Map",
		Type: mapTyp,
		Tag:  reflect.StructTag(`json:"map"`),
	}, {
		Name: "PtrValue",
		Type: ptrTyp,
		Tag:  reflect.StructTag(`json:"ptr_value"`),
	}, {
		Name: "Value",
		Type: typ,
		Tag:  reflect.StructTag(`json:"value"`),
	}, {
		Name: "PtrArray",
		Type: ptrArrayTyp,
		Tag:  reflect.StructTag(`json:"ptr_array"`),
	}, {
		Name: "Array",
		Type: arrayTyp,
		Tag:  reflect.StructTag(`json:"array"`),
	}, {
		Name: "PtrSlice",
		Type: ptrSliceTyp,
		Tag:  reflect.StructTag(`json:"ptr_slice"`),
	}, {
		Name: "Slice",
		Type: sliceTyp,
		Tag:  reflect.StructTag(`json:"slice"`),
	}})

	checkerVal = reflect.New(checkerTyp)

	checkerVal.Elem().Field(0).Set(reflect.MakeMap(ptrMapTyp))
	checkerVal.Elem().Field(1).Set(reflect.MakeMap(mapTyp))

	checkerVal.Elem().Field(6).Set(reflect.MakeSlice(ptrSliceTyp, 1, 1))
	checkerVal.Elem().Field(7).Set(reflect.MakeSlice(sliceTyp, 1, 1))

	return checkerVal
}

// assignGenericCodecChecker assigns all fields to v or the value v points to.
func assignGenericCodecChecker(checkerVal reflect.Value, v any) {
	keyVal := reflect.ValueOf("1")
	valPtr := reflect.ValueOf(v)
	val := valPtr.Elem()

	checkerVal.Elem().Field(0).SetMapIndex(keyVal, valPtr)
	checkerVal.Elem().Field(1).SetMapIndex(keyVal, val)

	checkerVal.Elem().Field(2).Set(valPtr)
	checkerVal.Elem().Field(3).Set(val)

	checkerVal.Elem().Field(4).Index(0).Set(valPtr)
	checkerVal.Elem().Field(5).Index(0).Set(val)

	checkerVal.Elem().Field(6).Index(0).Set(valPtr)
	checkerVal.Elem().Field(7).Index(0).Set(val)
}

// AssertMarshalText checks that the implementation of v's MarshalText works in
// all situations and results in the string s.  v must be a pointer.
//
// See https://github.com/dominikh/go-tools/issues/911.
func AssertMarshalText(t testing.TB, s string, v encoding.TextMarshaler) (ok bool) {
	t.Helper()

	// Create a checker value.
	checkerVal := newGenericCodecChecker(v)
	assignGenericCodecChecker(checkerVal, v)

	// Get the expected value.
	want, err := json.Marshal(newStringCodecChecker(s))
	require.NoErrorf(t, err, "marshaling expected value")

	// Marshal and check against the expected value.
	checker := checkerVal.Interface()
	b, err := json.Marshal(checker)
	require.NoErrorf(t, err, "marshaling checker value")

	return assert.Equal(t, string(want), string(b))
}

// AssertUnmarshalText checks that the implementation of v's UnmarshalText works
// in all situations and results in a value deeply equal to want.
func AssertUnmarshalText(t testing.TB, s string, v encoding.TextUnmarshaler) (ok bool) {
	t.Helper()

	// Create the expected value.
	want := newGenericCodecChecker(v)
	assignGenericCodecChecker(want, v)

	// Create the checker value.
	got := newGenericCodecChecker(v)

	// Marshal the expected data.
	strChecker := newStringCodecChecker(s)
	b, err := json.Marshal(strChecker)
	require.NoErrorf(t, err, "marshaling checker value")

	// Unmarshal into the checker value and compare.
	err = json.Unmarshal(b, got.Interface())
	require.NoErrorf(t, err, "unmarshaling value")

	return assert.Equal(t, want.Interface(), got.Interface())
}

// CleanupAndRequireSuccess sets a cleanup function which checks the error
// returned by f and fails the test using t if there is one.
func CleanupAndRequireSuccess(t testing.TB, f func() (err error)) {
	t.Helper()

	t.Cleanup(func() {
		err := f()
		require.NoError(t, err)
	})
}

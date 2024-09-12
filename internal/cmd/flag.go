package cmd

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/stringutil"
)

// uint32Value is an uint32 that can be defined as a flag for [flag.FlagSet].
type uint32Value uint32

// type check
var _ flag.Value = (*uint32Value)(nil)

// Set implements the [flag.Value] interface for *uint32Value.
func (i *uint32Value) Set(s string) (err error) {
	v, err := strconv.ParseUint(s, 0, 32)
	*i = uint32Value(v)

	return err
}

// String implements the [flag.Value] interface for *uint32Value.
func (i *uint32Value) String() (out string) {
	return strconv.FormatUint(uint64(*i), 10)
}

// float32Value is an float32 that can be defined as a flag for [flag.FlagSet].
type float32Value float32

// type check
var _ flag.Value = (*float32Value)(nil)

// Set implements the [flag.Value] interface for *float32Value.
func (i *float32Value) Set(s string) (err error) {
	v, err := strconv.ParseFloat(s, 32)
	*i = float32Value(v)

	return err
}

// String implements the [flag.Value] interface for *float32Value.
func (i *float32Value) String() (out string) {
	return strconv.FormatFloat(float64(*i), 'f', 3, 32)
}

// intSliceValue represent a struct with a slice of integers that can be defined
// as a flag for [flag.FlagSet].
type intSliceValue struct {
	// values is the pointer to a slice of integers to store parsed values.
	values *[]int

	// isSet is false until the corresponding flag is met for the first time.
	// When the flag is found, the default value is overwritten with zero value.
	isSet bool
}

// newIntSliceValue returns a pointer to intSliceValue with the given value.
func newIntSliceValue(p *[]int) (out *intSliceValue) {
	return &intSliceValue{
		values: p,
		isSet:  false,
	}
}

// type check
var _ flag.Value = (*intSliceValue)(nil)

// Set implements the [flag.Value] interface for *intSliceValue.
func (i *intSliceValue) Set(s string) (err error) {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("parsing integer slice arg %q: %w", s, err)
	}

	if !i.isSet {
		i.isSet = true
		*i.values = []int{}
	}

	*i.values = append(*i.values, v)

	return nil
}

// String implements the [flag.Value] interface for *intSliceValue.
func (i *intSliceValue) String() (out string) {
	if i == nil || i.values == nil {
		return ""
	}

	sb := &strings.Builder{}
	for idx, v := range *i.values {
		if idx > 0 {
			stringutil.WriteToBuilder(sb, ",")
		}

		stringutil.WriteToBuilder(sb, strconv.Itoa(v))
	}

	return sb.String()
}

// stringSliceValue represent a struct with a slice of strings that can be
// defined as a flag for [flag.FlagSet].
type stringSliceValue struct {
	// values is the pointer to a slice of string to store parsed values.
	values *[]string

	// isSet is false until the corresponding flag is met for the first time.
	// When the flag is found, the default value is overwritten with zero value.
	isSet bool
}

// newStringSliceValue returns a pointer to stringSliceValue with the given
// value.
func newStringSliceValue(p *[]string) (out *stringSliceValue) {
	return &stringSliceValue{
		values: p,
		isSet:  false,
	}
}

// type check
var _ flag.Value = (*stringSliceValue)(nil)

// Set implements the [flag.Value] interface for *stringSliceValue.
func (i *stringSliceValue) Set(s string) (err error) {
	if !i.isSet {
		i.isSet = true
		*i.values = []string{}
	}

	*i.values = append(*i.values, s)

	return nil
}

// String implements the [flag.Value] interface for *stringSliceValue.
func (i *stringSliceValue) String() (out string) {
	if i == nil || i.values == nil {
		return ""
	}

	sb := &strings.Builder{}
	for idx, v := range *i.values {
		if idx > 0 {
			stringutil.WriteToBuilder(sb, ",")
		}

		stringutil.WriteToBuilder(sb, v)
	}

	return sb.String()
}

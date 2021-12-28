#!/bin/sh

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '1' ]
then
	env
	set -x
	v_flags='-v=1'
	x_flags='-x=1'
elif [ "$verbose" -gt '0' ]
then
	set -x
	v_flags='-v=1'
	x_flags='-x=0'
else
	set +x
	v_flags='-v=0'
	x_flags='-x=0'
fi
readonly x_flags v_flags

set -e -f -u

go="${GO:-go}"
readonly go

ldflags="-s -w -X main.VersionString=${VERSION:-dev}"
readonly ldflags

parallelism="${PARALLELISM:-}"
readonly parallelism

# Use GOFLAGS for -p, because -p=0 simply disables the build instead of leaving
# the default value.
if [ "${parallelism}" != '' ]
then
        GOFLAGS="${GOFLAGS:-} -p=${parallelism}"
fi
readonly GOFLAGS
export GOFLAGS

# Allow users to specify a different output name.
out="${OUT:-dnsproxy}"
readonly out

o_flags="-o=${out}"
readonly o_flags

# Allow users to enable the race detector.  Unfortunately, that means that cgo
# must be enabled.
if [ "${RACE:-0}" -eq '0' ]
then
	cgo_enabled='0'
	race_flags='--race=0'
else
	cgo_enabled='1'
	race_flags='--race=1'
fi
readonly cgo_enabled race_flags

CGO_ENABLED="$cgo_enabled"
GO111MODULE='on'
export CGO_ENABLED GO111MODULE

"$go" build --ldflags "$ldflags" "$race_flags" --trimpath "$o_flags" "$v_flags" "$x_flags"

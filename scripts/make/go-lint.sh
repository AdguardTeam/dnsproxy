#!/bin/sh

# This comment is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
#
# AdGuard-Project-Version: 5

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '0' ]
then
	set -x
fi

# Set $EXIT_ON_ERROR to zero to see all errors.
if [ "${EXIT_ON_ERROR:-1}" -eq '0' ]
then
	set +e
else
	set -e
fi

set -f -u



# Source the common helpers, including not_found and run_linter.
. ./scripts/make/helper.sh



# Warnings

go_version="$( "${GO:-go}" version )"
readonly go_version

go_min_version='go1.20.11'
go_version_msg="
warning: your go version (${go_version}) is different from the recommended minimal one (${go_min_version}).
if you have the version installed, please set the GO environment variable.
for example:

	export GO='${go_min_version}'
"
readonly go_min_version go_version_msg

case "$go_version"
in
('go version'*"$go_min_version"*)
	# Go on.
	;;
(*)
	echo "$go_version_msg" 1>&2
	;;
esac



# Simple analyzers

# blocklist_imports is a simple check against unwanted packages.  The following
# packages are banned:
#
#   *  Packages errors and log are replaced by our own packages in the
#      github.com/AdguardTeam/golibs module.
#
#   *  Package io/ioutil is soft-deprecated.
#
#   *  Package reflect is often an overkill, and for deep comparisons there are
#      much better functions in module github.com/google/go-cmp.  Which is
#      already our indirect dependency and which may or may not enter the stdlib
#      at some point.
#
#      See https://github.com/golang/go/issues/45200.
#
#   *  Package sort is replaced by golang.org/x/exp/slices.
#
#   *  Package unsafe is… unsafe.
#
#   *  Package golang.org/x/net/context has been moved into stdlib.
#
# Currently, the only standard exception are files generated from protobuf
# schemas, which use package reflect.  If your project needs more exceptions,
# add and document them.
#
# TODO(a.garipov): Add deprecated packages golang.org/x/exp/maps and
# golang.org/x/exp/slices once all projects switch to Go 1.21.
blocklist_imports() {
	git grep\
		-e '[[:space:]]"errors"$'\
		-e '[[:space:]]"io/ioutil"$'\
		-e '[[:space:]]"log"$'\
		-e '[[:space:]]"reflect"$'\
		-e '[[:space:]]"sort"$'\
		-e '[[:space:]]"unsafe"$'\
		-e '[[:space:]]"golang.org/x/net/context"$'\
		-n\
		-- '*.go'\
		':!*.pb.go'\
		| sed -e 's/^\([^[:space:]]\+\)\(.*\)$/\1 blocked import:\2/'\
		|| exit 0
}

# method_const is a simple check against the usage of some raw strings and
# numbers where one should use named constants.
method_const() {
	git grep -F\
		-e '"DELETE"'\
		-e '"GET"'\
		-e '"PATCH"'\
		-e '"POST"'\
		-e '"PUT"'\
		-n\
		-- '*.go'\
		| sed -e 's/^\([^[:space:]]\+\)\(.*\)$/\1 http method literal:\2/'\
		|| exit 0
}

# underscores is a simple check against Go filenames with underscores.  Add new
# build tags and OS as you go.  The main goal of this check is to discourage the
# use of filenames like client_manager.go.
underscores() {
	underscore_files="$(
		git ls-files '*_*.go'\
			| grep -F\
			-e '_darwin.go'\
			-e '_generate.go'\
			-e '_linux.go'\
			-e '_others.go'\
			-e '_plan9.go'\
			-e '_test.go'\
			-e '_unix.go'\
			-e '_windows.go'\
			-e '_dnscrypt.go'\
			-e '_https.go'\
			-e '_quic.go'\
			-e '_tcp.go'\
			-e '_udp.go'\
			-v\
			| sed -e 's/./\t\0/'
	)"
	readonly underscore_files

	if [ "$underscore_files" != '' ]
	then
		echo 'found file names with underscores:'
		echo "$underscore_files"
	fi
}

# TODO(a.garipov): Add an analyzer to look for `fallthrough`, `goto`, and `new`?



# Checks

run_linter -e blocklist_imports

run_linter -e method_const

run_linter -e underscores

run_linter -e gofumpt --extra -e -l .

# TODO(a.garipov): golint is deprecated, find a suitable replacement.

run_linter "$GO" vet ./...

run_linter govulncheck ./...

# TODO(a.garipov): Enable for all.
run_linter gocyclo --over 10\
	./internal/bootstrap/\
	./internal/netutil/\
	./internal/osutil/\
	./internal/version/\
	./proxyutil/\
	./upstream/\
	;

run_linter gocyclo --over 20 ./main.go
run_linter gocyclo --over 18 ./fastip/
run_linter gocyclo --over 15 ./proxy/

# TODO(a.garipov): Enable for all.
run_linter gocognit --over 10\
	./internal/bootstrap/\
	./internal/osutil/\
	./internal/version/\
	./proxyutil/\
	./upstream/\
	;

run_linter gocognit --over 35 ./main.go
run_linter gocognit --over 31 ./proxy/
run_linter gocognit --over 29 ./fastip/
run_linter gocognit --over 14 ./internal/netutil/

run_linter ineffassign ./...

run_linter unparam ./...

git ls-files -- 'Makefile' '*.conf' '*.go' '*.mod' '*.sh' '*.yaml' '*.yml'\
	| xargs misspell --error\
	| sed -e 's/^/misspell: /'

run_linter looppointer ./...

run_linter nilness ./...

# TODO(a.garipov): Enable for all.
run_linter fieldalignment ./fastip/...
run_linter fieldalignment ./internal/...
run_linter fieldalignment ./proxyutil/...
run_linter fieldalignment ./upstream/...

run_linter -e shadow --strict ./...

run_linter gosec --quiet ./...

run_linter errcheck ./...

staticcheck_matrix='
darwin:  GOOS=darwin
freebsd: GOOS=freebsd
linux:   GOOS=linux
openbsd: GOOS=openbsd
windows: GOOS=windows
'
readonly staticcheck_matrix

echo "$staticcheck_matrix" | run_linter staticcheck --matrix ./...

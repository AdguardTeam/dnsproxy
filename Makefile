# Keep the Makefile POSIX-compliant.  We currently allow hyphens in
# target names, but that may change in the future.
#
# See https://pubs.opengroup.org/onlinepubs/9699919799/utilities/make.html.
.POSIX:

# This comment is used to simplify checking local copies of the
# Makefile.  Bump this number every time a significant change is made to
# this Makefile.
#
# AdGuard-Project-Version: 5

# Don't name these macros "GO" etc., because GNU Make apparently makes
# them exported environment variables with the literal value of
# "${GO:-go}" and so on, which is not what we need.  Use a dot in the
# name to make sure that users don't have an environment variable with
# the same name.
#
# See https://unix.stackexchange.com/q/646255/105635.
GO.MACRO = $${GO:-go}
VERBOSE.MACRO = $${VERBOSE:-0}

BRANCH = $$( git rev-parse --abbrev-ref HEAD )
DIST_DIR = build
GOAMD64 = v1
GOPROXY = https://proxy.golang.org|direct
GOTOOLCHAIN = go1.22.3
OUT = dnsproxy
RACE = 0
REVISION = $$( git rev-parse --short HEAD )
VERSION = 0

ENV = env\
	BRANCH="$(BRANCH)"\
	COMMIT='$(COMMIT)'\
	DIST_DIR='$(DIST_DIR)'\
	GO="$(GO.MACRO)"\
	GOAMD64='$(GOAMD64)'\
	GOPROXY='$(GOPROXY)'\
	GOTOOLCHAIN='$(GOTOOLCHAIN)'\
	OUT='$(OUT)'\
	PATH="$${PWD}/bin:$$( "$(GO.MACRO)" env GOPATH )/bin:$${PATH}"\
	RACE='$(RACE)'\
	REVISION="$(REVISION)"\
	VERBOSE="$(VERBOSE.MACRO)"\
	VERSION="$(VERSION)"\

# Keep the line above blank.

# Keep this target first, so that a naked make invocation triggers a
# full build.
build: go-deps go-build

init: ; git config core.hooksPath ./scripts/hooks

test: go-test

go-build: ; $(ENV)          "$(SHELL)" ./scripts/make/go-build.sh
go-deps:  ; $(ENV)          "$(SHELL)" ./scripts/make/go-deps.sh
go-lint:  ; $(ENV)          "$(SHELL)" ./scripts/make/go-lint.sh
go-test:  ; $(ENV) RACE='1' "$(SHELL)" ./scripts/make/go-test.sh
go-tools: ; $(ENV)          "$(SHELL)" ./scripts/make/go-tools.sh

go-upd-tools: ; $(ENV) "$(SHELL)" ./scripts/make/go-upd-tools.sh

go-check: go-tools go-lint go-test

# A quick check to make sure that all operating systems relevant to the
# development of the project can be typechecked and built successfully.
go-os-check:
	env GOOS='darwin'  "$(GO.MACRO)" vet ./...
	env GOOS='freebsd' "$(GO.MACRO)" vet ./...
	env GOOS='linux'   "$(GO.MACRO)" vet ./...
	env GOOS='openbsd' "$(GO.MACRO)" vet ./...
	env GOOS='windows' "$(GO.MACRO)" vet ./...

txt-lint: ; $(ENV) "$(SHELL)" ./scripts/make/txt-lint.sh

clean:   ; $(ENV) $(GO.MACRO) clean && rm -f -r '$(DIST_DIR)'

release: clean
	$(ENV) "$(SHELL)" ./scripts/make/build-release.sh

docker: release
	$(ENV) "$(SHELL)" ./scripts/make/build-docker.sh

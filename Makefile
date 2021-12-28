# Keep the Makefile POSIX-compliant.  We currently allow hyphens in
# target names, but that may change in the future.
#
# See https://pubs.opengroup.org/onlinepubs/9699919799/utilities/make.html.
.POSIX:

# Don't name this macro "GO", because GNU Make apparenly makes it an
# exported environment variable with the literal value of "${GO:-go}",
# which is not what we need.  Use a dot in the name to make sure that
# users don't have an environment variable with the same name.
#
# See https://unix.stackexchange.com/q/646255/105635.
GO.MACRO = $${GO:-go}
GOPROXY = https://goproxy.cn|https://proxy.golang.org|direct
DIST_DIR=build
OUT = dnsproxy
RACE = 0
VERBOSE = 0
VERSION = dev

ENV = env\
	DIST_DIR='$(DIST_DIR)'\
	GO="$(GO.MACRO)"\
	GOPROXY='$(GOPROXY)'\
	OUT='$(OUT)'\
	RACE='$(RACE)'\
	VERBOSE='$(VERBOSE)'\
	VERSION='$(VERSION)'\

# Keep the line above blank.

# Keep this target first, so that a naked make invocation triggers
# a full build.
build:   ; $(ENV) "$(SHELL)" ./scripts/make/build.sh

clean:   ; $(ENV) $(GO.MACRO) clean && rm -f -r '$(DIST_DIR)'
test:    ; $(ENV) RACE='1' "$(SHELL)" ./scripts/make/test.sh

release: clean
	$(ENV) "$(SHELL)" ./scripts/make/release.sh

# A quick check to make sure that all supported operating systems can be
# typechecked and built successfully.
os-check:
	env GOOS='darwin'  "$(GO.MACRO)" vet ./...
	env GOOS='freebsd' "$(GO.MACRO)" vet ./...
	env GOOS='linux'   "$(GO.MACRO)" vet ./...
	env GOOS='windows' "$(GO.MACRO)" vet ./...

#!/bin/sh

# This comment is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
#
# AdGuard-Project-Version: 4

# NOTE: If you use globs in markdownlint, you must remove '-f' flag.
set -e -f -o 'pipefail' -u

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '0' ]; then
	set -x
fi

markdownlint \
	./README.md \
	./docker/README.md \
	;

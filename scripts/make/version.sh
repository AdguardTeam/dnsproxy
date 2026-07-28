#!/bin/sh

# This script generates versions based on the current git tree state.  It should
# be sourced in scripts right after the initial environment processing.

version="${APP_VERSION:?please set APP_VERSION}"
if [ "$version" = '0' ]; then
	version="${GITHUB_REF:-}"
	version="${version##*/}"
fi

case "$version" in
v*)
	if ! printf '%s\n' "$version" | grep -E -e '^v[0-9]+\.[0-9]+\.[0-9]+$' -q; then
		printf "version is invalid '%s'\n" "$version" 1>&2

		exit 1
	fi
	;;
*)
	version='dev'
	;;
esac

readonly version

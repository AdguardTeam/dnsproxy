# syntax=docker/dockerfile:1

# This comment is used to simplify checking local copies of the Dockerfile.
# Bump this number every time a significant change is made to this Dockerfile.
#
# AdGuard-Project-Version: 13

# Dockerfile guidelines:
#
# 1. Make sure that Docker correctly caches layers, on a second build attempt it
#    must not run lint / test second time when it's not required.
#
# 2. Use BuildKit to improve the build performance (--mount=type=cache, etc).
#
# 3. Prefer using ARG instead of ENV when appropriate, as ARG does not create a
#    layer in the final image.  However, be careful with what you use ARG for.
#    Also, prefer to give ARGs sensible default values.
#
# 4. Use --output and the export stage if you need to get any output on the host
#    machine.
#
#    NOTE:  Only use --output with FROM scratch.
#
# 5. Use .dockerignore to prevent unnecessary files from being sent to the
#    Docker daemon, which can invalidate the cache.
#
# 6. Add a CACHE_BUSTER argument to stages to be able to rerun the stages if
#    needed.  Keep it in sync with the files in .github/workflows/.

ARG BASE_IMAGE=adguard/go-builder:1.26.5--1

# The builder stage is used to build release artifacts.  Real BRANCH, REVISION,
# and SOURCE_DATE_EPOCH must be used here.
FROM "$BASE_IMAGE" AS builder
ARG APP_VERSION=""
ARG BRANCH=master
ARG CACHE_BUSTER=0
ARG DIST_DIR="build"
ARG REVISION=0000000000000000000000000000000000000000
ARG SOURCE_DATE_EPOCH=0
ADD . /app/
WORKDIR /app
RUN \
	--mount=type=cache,id=gocache,target=/root/.cache/go-build \
	--mount=type=cache,id=gopath,target=/go \
<<-'EOF'
set -e -f -o 'pipefail' -u -x
make \
	APP_VERSION="${APP_VERSION}" \
	BRANCH="${BRANCH}" \
	DIST_DIR="${DIST_DIR}" \
	REVISION="${REVISION}" \
	SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
	VERBOSE=1 \
	release \
	;
EOF

# builder-exporter exports the build artifacts to the host machine so that they
# could be published.  This stage should only be used in a CI.
FROM scratch AS builder-exporter
ARG CACHE_BUSTER=0
ARG DIST_DIR="build"
COPY --from=builder "/app/$DIST_DIR" "$DIST_DIR"

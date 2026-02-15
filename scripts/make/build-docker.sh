#!/bin/sh

# TODO(a.garipov):  Improve arguments handling.

verbose="${VERBOSE:-0}"

if [ "$verbose" -gt '0' ]; then
	set -x
else
	set +x
fi

set -e -f -u

# Require these to be set.
commit="${REVISION:?please set REVISION}"
dist_dir="${DIST_DIR:?please set DIST_DIR}"
version="${VERSION:?please set VERSION}"
readonly commit dist_dir version

# Allow users to use sudo.
sudo_cmd="${SUDO:-}"
readonly sudo_cmd

docker_platforms="\
linux/386,\
linux/amd64,\
linux/arm/v6,\
linux/arm/v7,\
linux/arm64,\
linux/ppc64le"
readonly docker_platforms

build_date="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
readonly build_date

# Set DOCKER_IMAGE_NAME to 'adguard/dnsproxy' if you want (and are allowed)
# to push to DockerHub.
docker_image_name="${DOCKER_IMAGE_NAME:-dnsproxy-dev}"
readonly docker_image_name

# Set DOCKER_PUSH to '1' if you want (and are allowed) to push to DockerHub.
docker_push="${DOCKER_PUSH:-0}"
readonly docker_push

docker_version_tag="--tag=${docker_image_name}:${version}"
docker_channel_tag="--tag=${docker_image_name}:latest"

# If version is set to 'dev' or empty, only set the version tag and avoid
# polluting the "latest" tag.
if [ "${version:-}" = 'dev' ] || [ "${version:-}" = '' ]; then
	docker_channel_tag=""
fi

readonly docker_version_tag docker_channel_tag

# Copy the binaries into a new directory under new names, so that it's easier to
# COPY them later.  DO NOT remove the trailing underscores.  See file
# docker/build.Dockerfile.
dist_docker="${dist_dir}/docker"
readonly dist_docker

mkdir -p "$dist_docker"
cp "${dist_dir}/linux-386/dnsproxy" \
	"${dist_docker}/dnsproxy_linux_386_"
cp "${dist_dir}/linux-amd64/dnsproxy" \
	"${dist_docker}/dnsproxy_linux_amd64_"
cp "${dist_dir}/linux-arm64/dnsproxy" \
	"${dist_docker}/dnsproxy_linux_arm64_"
cp "${dist_dir}/linux-arm6/dnsproxy" \
	"${dist_docker}/dnsproxy_linux_arm_v6"
cp "${dist_dir}/linux-arm7/dnsproxy" \
	"${dist_docker}/dnsproxy_linux_arm_v7"
cp "${dist_dir}/linux-ppc64le/dnsproxy" \
	"${dist_docker}/dnsproxy_linux_ppc64le_"

# Prepare the default configuration for the Docker image.
cp ./config.yaml.dist "${dist_docker}/config.yaml"

# docker_build_opt_tag is a function that wraps the call of docker build command
# with optionally --tag flags.
docker_build_opt_tag() {
	if [ "$sudo_cmd" != '' ]; then
		set -- "$sudo_cmd"
	fi

	# Set the initial parameters.
	set -- \
		"$@" \
		docker \
		buildx \
		build \
		--build-arg BUILD_DATE="$build_date" \
		--build-arg DIST_DIR="$dist_dir" \
		--build-arg VCS_REF="$commit" \
		--build-arg VERSION="$version" \
		--platform "$docker_platforms" \
		--progress 'plain' \
		;

	# Append the channel tag, if any.
	if [ "$docker_channel_tag" != '' ]; then
		set -- "$@" "$docker_channel_tag"
	fi

	# Append the version tag.
	set -- "$@" "$docker_version_tag"

	# Push to DockerHub, if requested.
	if [ "$docker_push" -eq 1 ]; then
		set -- "$@" '--push'
	fi

	# Append the rest.
	set -- \
		"$@" \
		-f \
		./docker/build.Dockerfile \
		. \
		;

	# Call the command with the assembled parameters.
	"$@"
}

docker_build_opt_tag

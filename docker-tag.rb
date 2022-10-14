# # on local machine, you may need 
# `docker buildx create --name mycontext1 --driver docker-container --use --bootstrap`
# `docker run --rm --privileged tonistiigi/binfmt:latest --install all`
require "./version"

REGISTRY = "docker.io"
DOCKER_USER = "initdc"
DOCKER_IMAGE = "demo"
# VERSION = "v0.0.1"
LATEST = "scratch"
# the base of docker `FROM scratch`, if not, set: { false | "" }
ACTION = "--push"
# options: { --push | --load | "" }

TARGET_DIR = "target"

# docker buildx ls
# scratch image base
BUILDER_SUPPORT = [
    "linux/amd64",
    "linux/arm64",
    "linux/riscv64",
    "linux/ppc64le",
    "linux/s390x",
    "linux/386",
    "linux/mips64le",
    "linux/mips64",
    "linux/arm/v7",
    "linux/arm/v6"
]

IMAGE_SUPPORT = {
    "scratch": BUILDER_SUPPORT,

    # below info from Picture text recognition
    # https://hub.docker.com/_/alpine/tags?page=1&name=edge
    "alpine": [
        "linux/386",
        "linux/amd64",
        "linux/arm/v6",
        "linux/arm/v7",
        "linux/arm64/v8",
        "linux/ppc64le",
        "linux/riscv64",
        "linux/s390x"
    ],

    # https://hub.docker.com/_/busybox/tags?page=1&name=latest
    "busybox": [
        "linux/386",
        "linux/amd64",
        "linux/arm/v6",
        "linux/arm/v5",
        "linux/arm/v7",
        "linux/arm64/v8",
        "linux/mips64le",
        "linux/ppc64le",
        "linux/riscv64",
        "linux/s390x"
    ],

    # https://hub.docker.com/_/ubuntu/tags?page=1&name=22.04
    "ubuntu": [
        "linux/amd64",
        "linux/arm/v7",
        "linux/arm64/v8",
        "linux/ppc64le",
        "linux/riscv64",
        "linux/s390x"
    ]
}

# add base as you need for following build
BASE_TAG = {
    # "scratch": "",
    "alpine": "alpine",
    # "busybox": "busybox",
    "ubuntu": ""
}

bin_exist = {}

for target_platform in BUILDER_SUPPORT
    if system("test -f #{TARGET_DIR}/#{target_platform}/*")
        bin_exist.store target_platform, true
    else
        bin_exist.store target_platform, false
    end
end
# p bin_exist

BASE_TAG.each do |base, distro|
    build_tp = []

    dockerfile = base.to_s == "scratch" ? "Dockerfile" : "Dockerfile.#{base}"
    # dockerfile = base.to_s == "scratch" ? "Dockerfile" : "#{base}.Dockerfile"
    # p dockerfile

    os_arch = IMAGE_SUPPORT.fetch :"#{base}"
    for tp in os_arch.to_a
        target_platform = tp == "linux/arm64/v8" ? "linux/arm64" : tp
        if BUILDER_SUPPORT.include?(target_platform)
            if bin_exist.fetch "#{target_platform}"
                # print target_platform + ","
                build_tp.push(target_platform)
            end
        end
    end
    # print "\n"

    registry = ENV['REGISTRY'] || REGISTRY
    docker_user = ENV['DOCKER_USER'] || DOCKER_USER
    docker_image = ENV['DOCKER_IMAGE'] || DOCKER_IMAGE
    imagename = ENV['IMAGENAME'] || "#{docker_user}/#{docker_image}"
    version = ARGV[0] || VERSION

    tag = distro.to_s == "" ? version : "#{version}-#{distro}"
    # p tag

    if build_tp.length > 0
        cmd = "docker buildx build --platform #{build_tp.join ","} -t #{registry}/#{imagename}:#{tag} -f #{dockerfile} . #{ACTION}"
        p cmd
        IO.popen(cmd) do |r|
            puts r.readlines
        end

        if LATEST != false and LATEST == base.to_s
            `docker buildx build --platform #{build_tp.join ","} -t #{registry}/#{imagename}:latest -f #{dockerfile} . #{ACTION}`
        end
    end
end

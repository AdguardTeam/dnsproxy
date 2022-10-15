require "./version"

PROGRAM = "dnspoxy"
# VERSION = "v0.0.1"
BUILD_CMD = "go build -o"
# used in this way:
# ENV BUILD_CMD OUTPUT_PATH
TEST_CMD = "go test"

TARGET_DIR = "target"
UPLOAD_DIR = "upload"

def clean
    `rm -rf #{TARGET_DIR} #{UPLOAD_DIR}`
end

# go tool dist list
OS_ARCH = [
    # "aix/ppc64",
    "android/386",
    "android/amd64",
    "android/arm",
    "android/arm64",
    "darwin/amd64",
    "darwin/arm64",
    # "dragonfly/amd64",
    "freebsd/386",
    "freebsd/amd64",
    "freebsd/arm",
    "freebsd/arm64",
    # "illumos/amd64",
    "ios/amd64",
    "ios/arm64",
    "js/wasm",
    "linux/386",
    "linux/amd64",
    "linux/arm",
    "linux/arm64",
    "linux/mips",
    "linux/mips64",
    "linux/mips64le",
    "linux/mipsle",
    "linux/ppc64",
    "linux/ppc64le",
    "linux/riscv64",
    "linux/s390x",
    "netbsd/386",
    "netbsd/amd64",
    "netbsd/arm",
    "netbsd/arm64",
    "openbsd/386",
    "openbsd/amd64",
    "openbsd/arm",
    "openbsd/arm64",
    "openbsd/mips64",
    # "plan9/386",
    # "plan9/amd64",
    # "plan9/arm",
    # "solaris/amd64",
    "windows/386",
    "windows/amd64",
    "windows/arm",
    "windows/arm64"
]

ARM = ["5", "6", "7"]

TEST_OS_ARCH = [
    "darwin/amd64",
    "darwin/arm64",
    "linux/386",
    "linux/amd64",
    "linux/arm",
    "linux/arm64",
    "linux/riscv64",
    "windows/386",
    "windows/amd64",
    "windows/arm64"
]

LESS_OS_ARCH = [
    "linux/amd64",
    "linux/arm64"
]

version = ARGV[0][0] == "v" ? ARGV[0] : VERSION
test_bin = ARGV[0] == "test" || false
less_bin = ARGV[0] == "less" || false

run_test = ARGV.include? "--run-test" || false 
catch_error = ARGV.include? "--catch-error" || false

os_arch = OS_ARCH
os_arch = TEST_OS_ARCH if test_bin
os_arch = LESS_OS_ARCH if less_bin

# on local machine, you may re-run this script
if test_bin || less_bin
    clean
end
`mkdir -p #{TARGET_DIR} #{UPLOAD_DIR}`

for target_platform in os_arch do
    tp_array = target_platform.split('/')
    os = tp_array[0]
    architecture = tp_array[1]

    program_bin = os != "windows" ? PROGRAM : "#{PROGRAM}.exe"

    if architecture == "arm" 
        for variant in ARM do
            puts "GOOS=#{os} GOARCH=#{architecture} GOARM=#{variant}"

            if run_test
                test_cmd = "GOOS=#{os} GOARCH=#{architecture} GOARM=#{variant} #{TEST_CMD}"
                puts test_cmd
                test_result = system test_cmd
                if catch_error and !test_result
                    return
                else
                    puts "skip testing for #{os}/#{architecture}/#{variant}"
                end
            end

            upload_bin = os != "windows" ? "#{PROGRAM}-#{version}-#{os}-#{architecture}-#{variant}" : "#{PROGRAM}-#{version}-#{os}-#{architecture}-#{variant}.exe"

            `GOOS=#{os} GOARCH=#{architecture} GOARM=#{variant} #{BUILD_CMD} #{TARGET_DIR}/#{os}/#{architecture}/v#{variant}/#{program_bin}`
            `ln #{TARGET_DIR}/#{os}/#{architecture}/v#{variant}/#{program_bin} #{UPLOAD_DIR}/#{upload_bin}`
        end
    else
        puts "GOOS=#{os} GOARCH=#{architecture}"

        if run_test
            test_cmd = "GOOS=#{os} GOARCH=#{architecture} #{TEST_CMD}"
            puts test_cmd
            test_result = system test_cmd
            if catch_error and !test_result
                return
            else
                puts "skip testing for #{os}/#{architecture}"
            end            
        end

        upload_bin = os != "windows" ? "#{PROGRAM}-#{version}-#{os}-#{architecture}" : "#{PROGRAM}-#{version}-#{os}-#{architecture}.exe"

        `GOOS=#{os} GOARCH=#{architecture} #{BUILD_CMD} #{TARGET_DIR}/#{os}/#{architecture}/#{program_bin}`
        `ln #{TARGET_DIR}/#{os}/#{architecture}/#{program_bin} #{UPLOAD_DIR}/#{upload_bin}`
    end
end

# cmd = "file #{UPLOAD_DIR}/**"
# IO.popen(cmd) do |r|
#     puts r.readlines
# end

file = "#{UPLOAD_DIR}/BINARYS"
IO.write(file, "")

cmd = "tree #{TARGET_DIR}"
IO.popen(cmd) do |r|
    rd = r.readlines
    puts rd

    for o in rd
        IO.write(file, o, mode: "a")
    end
end

Dir.chdir UPLOAD_DIR do
    file = "SHA256SUM"
    IO.write(file, "")

    cmd = "sha256sum *"
    IO.popen(cmd) do |r|
        rd = r.readlines

        for o in rd
            if ! o.include? "SHA256SUM" and ! o.include? "BINARYS"
                print o
                IO.write(file, o, mode: "a")
            end
        end
    end
end

# `docker buildx build --platform linux/amd64 -t demo:amd64 . --load`
# cmd = "docker run demo:amd64"
# IO.popen(cmd) do |r|
#     puts r.readlines
# end
NAME=dnsproxy

.PHONY: default
default: build

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(patsubst %/,%,$(dir $(mkfile_path)))
GOPATH := $(mkfile_dir)/build/gopath
ANDROID_HOME := $(ANDROID_HOME)
ANDROID_NDK := $(ANDROID_HOME)/ndk-bundle

clean:
	rm -rf build
	rm -f $(NAME).aar
	rm -f $(NAME)-sources.jar

build:
	mkdir -p $(GOPATH)/src/github.com/AdguardTeam/dnsproxy
	if [ ! -h $(GOPATH)/src/github.com/AdguardTeam/dnsproxy ]; then rm -rf $(GOPATH)/src/github.com/AdguardTeam/dnsproxy && ln -fs $(mkfile_dir)/.. $(GOPATH)/src/github.com/AdguardTeam/dnsproxy; fi
	GOPATH=$(GOPATH) GO111MODULE=off go get -v -d .
	GOPATH=$(GOPATH) GO111MODULE=off go get -v golang.org/x/mobile/cmd/gomobile
	GOPATH=$(GOPATH) GO111MODULE=off PATH=$(GOPATH)/bin:$(PATH) gomobile init -ndk $(ANDROID_NDK)
	GOPATH=$(GOPATH) GO111MODULE=off PATH=$(GOPATH)/bin:$(PATH) ANDROID_HOME=$(ANDROID_HOME) gomobile bind -target=android -o $(NAME).aar github.com/AdguardTeam/dnsproxy/mobile

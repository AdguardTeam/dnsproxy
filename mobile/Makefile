NAME=dnsproxy

.PHONY: default
default: build

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(patsubst %/,%,$(dir $(mkfile_path)))
GOPATH := $(mkfile_dir)/build
ANDROID_HOME := $(ANDROID_HOME)
ANDROID_NDK := $(ANDROID_HOME)/ndk-bundle

clean: cleanfast
	rm -rf build

cleanfast:
	rm -f $(NAME).aar
	rm -f $(NAME)-sources.jar
	rm -rf $(NAME).framework

gopath:
	mkdir -p $(GOPATH)/src/github.com/AdguardTeam/dnsproxy
	if [ ! -h $(GOPATH)/src/github.com/AdguardTeam/dnsproxy ]; then rm -rf $(GOPATH)/src/github.com/AdguardTeam/dnsproxy && ln -fs $(mkfile_dir)/.. $(GOPATH)/src/github.com/AdguardTeam/dnsproxy; fi
	cp -rf $(GOPATH)/../../vendor/github.com/* $(GOPATH)/src/github.com/
	cp -rf $(GOPATH)/../../vendor/golang.org/* $(GOPATH)/src/golang.org/
	cp -rf $(GOPATH)/../../vendor/gopkg.in/* $(GOPATH)/src/gopkg.in/
	GOPATH=$(GOPATH) GO111MODULE=off go get -v golang.org/x/mobile/cmd/gomobile
	# Temporary -- reset gomobile to the commit that we use with the NDK r19
	cd $(GOPATH)/src/golang.org/x/mobile/cmd/gomobile && git reset --hard a42111704963f4f0d1266674e1e97489aa8dcca0
	GOPATH=$(GOPATH) GO111MODULE=off go get -v golang.org/x/mobile/cmd/gomobile

android: check-env-android gopath
	GOPATH=$(GOPATH) GO111MODULE=off PATH=$(GOPATH)/bin:$(PATH) gomobile init -ndk $(ANDROID_NDK)
	GOPATH=$(GOPATH) GO111MODULE=off PATH=$(GOPATH)/bin:$(PATH) ANDROID_HOME=$(ANDROID_HOME) gomobile bind -target=android -o $(NAME).aar github.com/AdguardTeam/dnsproxy/mobile

ios: gopath
	GOPATH=$(GOPATH) GO111MODULE=off PATH=$(GOPATH)/bin:$(PATH) gomobile init
	GOPATH=$(GOPATH) GO111MODULE=off PATH=$(GOPATH)/bin:$(PATH) gomobile bind -ldflags="-s -w" -target=ios -o $(NAME).framework github.com/AdguardTeam/dnsproxy/mobile

build: android ios

check-env-android:
	@ if [ "$(ANDROID_HOME)" = "" ]; then \
		echo "Environment variable ANDROID_HOME not set"; \
		exit 1; \
	fi
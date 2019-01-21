NAME=dnsproxy
BASE_BUILDDIR=build
BUILDNAME=$(GOOS)-$(GOARCH)
BUILDDIR=$(BASE_BUILDDIR)/$(BUILDNAME)
VERSION?=dev

ifeq ($(GOOS),windows)
  ext=.exe
  archiveCmd=zip -9 -r $(NAME)-$(BUILDNAME)-$(VERSION).zip $(BUILDNAME)
else
  ext=
  archiveCmd=tar czpvf $(NAME)-$(BUILDNAME)-$(VERSION).tar.gz $(BUILDNAME)
endif

.PHONY: default
default: build

build: clean test
	go build

release: check-env-release
	mkdir -p $(BUILDDIR)
	cp LICENSE $(BUILDDIR)/
	cp README.md $(BUILDDIR)/
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(BUILDDIR)/$(NAME)$(ext)
	cd $(BASE_BUILDDIR) ; $(archiveCmd)
#
#win32:
#	mkdir -p $(BUILDDIR)/win32
#	cp LICENSE $(BUILDDIR)/win32/
#	cp README $(BUILDDIR)/win32/
#	GOOS=windows GOARCH=386 go build -o $(BUILDDIR)/win32/$(NAME).exe
#
#win64:
#	mkdir -p $(BUILDDIR)/win64
#	cp LICENSE $(BUILDDIR)/win64/
#	GOOS=windows GOARCH=amd64 go build -o $(BUILDDIR)/win64/$(NAME).exe
#
#linux-386:
#	mkdir -p $(BUILDDIR)/linux-386
#	cp LICENSE $(BUILDDIR)/linux-386/
#	GOOS=linux GOARCH=386 go build -o $(BUILDDIR)/linux-386/$(NAME)
#
#linux-amd64:
#	mkdir -p $(BUILDDIR)/linux-amd64
#	cp LICENSE $(BUILDDIR)/linux-amd64/
#	GOOS=linux GOARCH=amd64 go build -o $(BUILDDIR)/linux-amd64/$(NAME)
#
#macos:
#	mkdir -p $(BUILDDIR)/macos
#	cp LICENSE $(BUILDDIR)/macos/
#	GOOS=darwin GOARCH=amd64 go build -o $(BUILDDIR)/linux-amd64/$(NAME)

test:
	go test -race -v -bench=. ./...

clean:
	go clean
	rm -rf $(BASE_BUILDDIR)

check-env-release:
	@ if [ "$(GOOS)" = "" ]; then \
		echo "Environment variable GOOS not set"; \
		exit 1; \
	fi
	@ if [ "$(GOARCH)" = "" ]; then \
		echo "Environment variable GOOS not set"; \
		exit 1; \
	fi
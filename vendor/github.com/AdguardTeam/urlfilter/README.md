[![Build Status](https://travis-ci.com/AdguardTeam/urlfilter.svg?branch=master)](https://travis-ci.com/AdguardTeam/urlfilter)
[![Code Coverage](https://img.shields.io/codecov/c/github/AdguardTeam/urlfilter/master.svg)](https://codecov.io/github/AdguardTeam/urlfilter?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/AdguardTeam/urlfilter)](https://goreportcard.com/report/AdguardTeam/urlfilter)
[![GolangCI](https://golangci.com/badges/github.com/AdguardTeam/urlfilter.svg)](https://golangci.com/r/github.com/AdguardTeam/urlfilter)
[![Go Doc](https://godoc.org/github.com/AdguardTeam/urlfilter?status.svg)](https://godoc.org/github.com/AdguardTeam/urlfilter)

# AdGuard content blocking library

Pure GO library that implements AdGuard filtering rules syntax.

You can learn more about AdGuard filtering rules syntax from [this article](https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters).

#### TODO:

* [X] Basic filtering rules
    * [X] Core blocking syntax
    * [X] Basic engine
    * [X] Basic rules validation (don't match everything, unexpected modifiers, etc)
    * [ ] Domain modifier semantics: https://github.com/AdguardTeam/AdguardBrowserExtension/issues/1474
* [X] Benchmark basic rules matching
* [X] Hosts matching rules
    * [X] /etc/hosts matching
    * [X] $badfilter support for host-blocking network rules
* [X] Memory optimization
* [ ] Tech document
* [ ] Cosmetic rules
    * [X] Basic element hiding and CSS rules
        * [ ] Proper CSS rules validation
    * [ ] ExtCSS rules
    * [ ] Scriptlet rules
    * [ ] JS rules
* [ ] Proxy implementation
    * [X] Simple MITM proxy example
    * [X] Add cosmetic filters to the proxy example
    * [X] Handling cosmetic modifiers $elemhide, $generichide, $jsinject
    * [X] (!) Server certificate verification - it should pass badssl.com/dashboard/
    * [ ] Unit tests coverage
    * [ ] Fix TODOs
    * [ ] Proxy - handle CSP (including <meta> tags with CSP)
    * [X] Proxy - proper blocking page code
    * [ ] Proxy - unblocking via a temporary cookie
    * [X] Proxy - content script caching
    * [X] Proxy - content script compression
    * [ ] Proxy - brotli support (see [here](https://github.com/andybalholm/brotli))
    * [ ] Content script - babel plugin
    * [ ] Content script - apply ExtCSS rules
    * [ ] Content script - styles protection
    * [ ] Content script - JS unit tests
    * [ ] Content script - GO unit tests
* [ ] HTML filtering rules
* [ ] Advanced modifiers
    * [X] $important
    * [ ] $replace
    * [ ] $csp
    * [ ] $cookie
    * [ ] $redirect
    * [X] $badfilter
    
#### How to use

TODO

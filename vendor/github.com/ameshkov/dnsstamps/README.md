[![Build Status](https://travis-ci.org/ameshkov/dnsstamps.svg?branch=master)](https://travis-ci.org/ameshkov/dnsstamps)
[![Code Coverage](https://img.shields.io/codecov/c/github/ameshkov/dnsstamps/master.svg)](https://codecov.io/github/ameshkov/dnsstamps?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/ameshkov/dnsstamps)](https://goreportcard.com/report/ameshkov/dnsstamps)
[![Go Doc](https://godoc.org/github.com/ameshkov/dnsstamps?status.svg)](https://godoc.org/github.com/ameshkov/dnsstamps)

# DNS Stamps

Implementation of [DNS stamps](https://dnscrypt.info/stamps-specifications/):

> Server stamps encode all the parameters required to connect to a secure DNS server as a single string.
Think about stamps as QR code, but for DNS.

Half of the code comes from the DNS stamps author: https://github.com/jedisct1/go-dnsstamps

This library was made for a single purpose - to add missing stamps implementations: plain DNS and DNS-over-TLS.

TODO: backport to https://github.com/jedisct1/go-dnsstamps
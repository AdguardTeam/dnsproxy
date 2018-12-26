# Mobile API

This package is a mobile API for the `dnsproxy`.

We are using [gomobile](https://github.com/golang/go/wiki/Mobile) to build mobile bindings as it is explained in the documentation.

## How to build

You will need go v1.11 or newer.

```
$ export ANDROID_HOME=PATH_TO_ANDROID_SDK
$ make clean
$ make
```

## TODO

There is a known issue with `gomobile` [not supporting](https://github.com/golang/go/issues/27234) go modules.
Unfortunately, until this issue is resolved, we have to use a complicated make file

* [X] Android library build
* [ ] iOS library build
* [ ] Update the build script once go modules support is added to `gomobile`
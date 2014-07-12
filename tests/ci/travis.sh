#!/bin/sh -ex
# Install build-depends
yes | sudo mk-build-deps -i
# Build packages and run tests during building.
yes | debuild -e CC -e CXX --prepend-path="/usr/local/bin/" -uc -us

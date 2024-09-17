#!/bin/bash
INCLUDEFLAGS=-Isrc
LIBCURLCLIBS="-lcurl"
ROCKSDBCFLAGS=`pkgconf --cflags rocksdb`
ROCKSDBLIBS=`pkgconf --libs-only-l rocksdb`
LIBXML2FLAGS=`pkgconf --libs --cflags  libxml-2.0`
OPENSSLLIBS=`pkgconf --libs openssl`
LIBBASE64LIBS="-Llibraries/lib -lbase64 -Ilibraries/include"
FILESC="src/main.cpp src/proxy.cpp src/city.cpp"

clang++ $ROCKSDBCFLAGS $OPENSSLLIBS $LIBCURLCLIBS $ROCKSDBLIBS $INCLUDEFLAGS $LIBXML2FLAGS $@ $FILESC $LIBBASE64LIBS -o main

# if [ $? == 0 ]; then
#     ./main
# fi
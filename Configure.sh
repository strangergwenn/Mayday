#!/bin/sh

src=`pwd`
build="build/Linux"

if [ ! -d "$build" ] ; then
	mkdir -p $build
fi

cd $build

cmake -G "Unix Makefiles" -DCMAKE_STAGING_PREFIX="$src" "$src" "$@"

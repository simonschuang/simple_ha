#!/bin/bash

set -x
Package=libslb
Version=1.0
Architecture=amd64
Name=${Package}_${Version}_${Architecture}
BuildRoot=/tmp

set -e

CurDIR=`pwd`

# Create DEB package folder
rm -rf $BuildRoot/$Name
mkdir -p $BuildRoot/$Name/DEBIAN

# Build
make clean
make

# Install to DEB package folder
make install BUILD_ROOT="$BuildRoot/$Name"

# Copy DEB files 
cp deb/* $BuildRoot/$Name/DEBIAN/

# Make files executable
chmod +x $BuildRoot/$Name/DEBIAN/rules
chmod +x $BuildRoot/$Name/DEBIAN/postinst
chmod +x $BuildRoot/$Name/DEBIAN/prerm

# Build deb package
rm -f $BuildRoot/$Name.deb
find $BuildRoot/$Name -type d | xargs chmod 755
dpkg-deb --build $BuildRoot/$Name
mv $BuildRoot/$Name.deb ../../../../packages/

# Clean Temp
rm -rf $BuildRoot/$Name
make clean

set +e
set +x

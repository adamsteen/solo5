#!/bin/sh

export PREFIX="$PWD/.cross"
export TARGET=x86_64-elf
export PATH="$PREFIX/bin:$PATH"
export CC=egcc
export CXX=eg++

mkdir build-cross-compiler && \
cd build-cross-compiler && \
curl -O http://gnu.uberglobalmirror.com/binutils/binutils-2.28.tar.gz && \
tar zxvf binutils-2.28.tar.gz && \
mkdir build-binutils && \
cd build-binutils && \
../binutils-2.28/configure --target=$TARGET --prefix="$PREFIX" --with-sysroot --disable-nls --disable-werror && \
gmake && \
gmake install && \
echo "\nbinutils successfully built\n" && \
cd .. && \
curl -O http://gnu.uberglobalmirror.com/gcc/gcc-4.9.4/gcc-4.9.4.tar.gz && \
tar zxvf gcc-4.9.4.tar.gz && \
mkdir build-gcc && \
cd build-gcc && \
../gcc-4.9.4/configure --target=$TARGET --prefix="$PREFIX" --disable-nls --enable-languages=c,c++ --without-headers && \
gmake all-gcc && \
gmake all-target-libgcc && \
gmake install-gcc && \
gmake install-target-libgcc && \
echo "\ngcc successfully built\n" && \
cd ../../ && \
rm -rf build-cross-compiler && \
echo "\nsuccessfully built a cross compiler\n"

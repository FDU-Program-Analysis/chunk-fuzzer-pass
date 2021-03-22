# Clang build config
## libjpeg , libpng
```
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure --disable-shared --prefix=$PREFIX
```

## jasper
```
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" cmake -G "Unix Makefiles" -B$YOUR_PATH/build-clang   -DCMAKE_INSTALL_PREFIX=$PREFIX -DJAS_ENABLE_SHARED=false
```

## ffmpeg
```
./configure --cc=gclang --cxx=gclang++ --extra-cflags='-O0 -g -fembed-bitcode -fno-discard-value-names' --extra-cxxflags='-O0 -g -fembed-bitcode -fno-discard-value-names' --prefix=$PREFIX --disable-runtime-cpudetect --disable-optimizations --disable-mmx --disable-mmxext --disable-sse --disable-sse2 --disable-sse3 --disable-ssse3 --disable-sse4 --disable-sse42 --disable-avx --disable-avx2 --disable-avx512 --disable-stripping --disable-autodetect --disable-doc --disable-pthreads --disable-w32threads --disable-os2threads --disable-network
```

## libav
```
./configure --cc=gclang --extra-cflags='-O0 -g -fembed-bitcode -fno-discard-value-names' --prefix=$PREFIX --disable-doc --disable-pthreads --disable-w32threads --disable-network --disable-bzlib --disable-gnutls --disable-openssl --disable-zlib --disable-mmx --disable-mmxext --disable-sse --disable-sse2 --disable-sse3 --disable-ssse3 --disable-sse4 --disable-sse42 --disable-avx --disable-avx2 --disable-yasm
```

## wavpack
```
CC=gclang CXX=gclang++ CFLAGS="-O0 -g -fno-discard-value-names" ./configure --disable-asm --enable-man --enable-rpath --enable-tests --disable-dsd --enable-legacy --enable-shared=no --prefix=$PREFIX
```


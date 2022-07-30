cmake_minimum_required(VERSION 3.22.1)
project(mm)

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    add_compile_options(-DDEBUG)
    add_compile_options(-g3 -O0)
else ()
    add_compile_options(-DNDEBUG)
    add_compile_options(-fvisibility=hidden -fvisibility-inlines-hidden)
    add_compile_options(-fomit-frame-pointer -ffunction-sections -fdata-sections -fno-stack-protector)
    add_link_options(-Wl,--gc-sections)
    add_link_options(-Wl,--strip-all)
    # add_compile_options("-flto")
    # link_libraries("-fuse-ld=lld")
endif ()

enable_language(C ASM)

if (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "arm64-v8a")
    set(ARCH_SRC
            src/main/cpp/kernel/arm64/checksum.c)
elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "armeabi-v7a")
    set(ARCH_SRC
            src/main/cpp/kernel/arm/csumipv6.S
            src/main/cpp/kernel/arm/csumpartial.S)
endif ()

add_library(tunnel SHARED
        ${ARCH_SRC}
        src/main/cpp/tunnel.cpp)

target_link_libraries(tunnel PRIVATE log)

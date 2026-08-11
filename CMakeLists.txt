#
# MIT License
#
# Copyright (c) 2020-2026 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

cmake_minimum_required(VERSION 3.10.0)
project(libpwny VERSION 1.0.0)

option(DEBUG "Build in debug mode" OFF)
option(MAIN "Build main executable" OFF)
option(BUNDLE "Build as bundle (macOS/iOS)" OFF)
option(SHARED "Build shared object instead" OFF)
option(PLUGINS "Build tab plugins" OFF)

set(SOURCE src/main/main.c CACHE STRING "File to build as executable")

if (DEBUG)
    add_compile_definitions(DEBUG)
endif()

# Strip build paths from binaries (prevents source path leaks)
add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=./)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    include_directories(include/posix)
    file(GLOB PWNY_SOURCES src/*.c src/posix/*.c)

    add_compile_definitions(__macintosh__)

    if(BUNDLE)
        add_link_options(-bundle)
    endif()

elseif(CMAKE_SYSTEM_NAME STREQUAL iOS)
    include_directories(include/posix)
    file(GLOB PWNY_SOURCES src/*.c src/posix/*.c)

    add_compile_definitions(__iphone__)

    if(BUNDLE)
        add_compile_definitions(IS_BUNDLE)
    endif()

elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
    include_directories(include/posix)
    file(GLOB PWNY_SOURCES src/*.c src/posix/*.c)
    add_compile_definitions(__linux__)

else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}. Supported: Linux, Darwin, iOS.")
endif()

list(FILTER PWNY_SOURCES EXCLUDE REGEX "tab_lite\\.c$")
add_library(pwny STATIC ${PWNY_SOURCES})

set_property(TARGET pwny PROPERTY C_STANDART 99)
set_property(TARGET pwny PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(pwny PROPERTIES OUTPUT_NAME pwny)
include_directories(include api deps/build/${CMAKE_SYSTEM_TARGET}/include)

if(MAIN)
    file(GLOB MAIN_SOURCES ${SOURCE})
    add_executable(main ${MAIN_SOURCES})

    target_link_directories(main PRIVATE deps/build/${CMAKE_SYSTEM_TARGET}/lib)
    target_link_libraries(main PRIVATE
        pwny
        sigar
        eio
        ev
        curl
        z
        mbedx509
        mbedtls
        mbedcrypto
        pthread
    )

    if(EXISTS ${CMAKE_SOURCE_DIR}/deps/build/${CMAKE_SYSTEM_TARGET}/lib/libpawn.a)
        target_link_libraries(main PRIVATE pawn)
    else()
        message(WARNING "libpawn.a not found for ${CMAKE_SYSTEM_TARGET}, building without pawn")
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL Linux)
        if(EXISTS ${CMAKE_SOURCE_DIR}/deps/build/${CMAKE_SYSTEM_TARGET}/lib/libinjector.a)
            target_link_libraries(main PRIVATE injector)
        else()
            message(WARNING "libinjector.a not found for ${CMAKE_SYSTEM_TARGET}, building without injector")
        endif()
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
        target_compile_options(main PRIVATE -fobjc-arc)
        target_link_libraries(main PRIVATE "-framework Foundation"
                                           "-framework IOKit"
                                           "-framework AVFoundation"
                                           "-framework AppKit"
                                           "-framework CoreMedia"
                                           "-framework CoreImage")

    elseif(CMAKE_SYSTEM_NAME STREQUAL iOS)
        target_link_libraries(main PRIVATE "-framework Foundation"
                                           "-framework UIKitCore"
                                           "-framework AVFCapture"
                                           "-framework AVFCore"
                                           "-framework AVFAudio"
                                           "-framework CoreMedia"
                                           "-framework CoreVideo"
                                           "-framework CoreGraphics"
                                           "-framework CoreImage"
                                           "-framework BackBoardServices"
                                           "-framework MediaRemote"
                                           "-framework MediaPlayer"
                                           "-framework SpringBoardServices"
                                           "-framework CoreLocation"
                                           "MobileGestalt")

    elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
        target_link_libraries(main PRIVATE pthread)
        if(SHARED)
            target_link_options(main PRIVATE -shared -fPIC)
        else()
            if(CMAKE_SYSTEM_PROCESSOR STREQUAL x64)
                target_link_options(main PRIVATE -static-pie -Wl,-z,max-page-size=4096)
            else()
                target_link_options(main PRIVATE -static-pie)
            endif()
        endif()
    endif()

    # Install main executable to pwny/templates/<triplet>.exe
    set(TEMPLATES_DIR ${CMAKE_SOURCE_DIR}/pwny/templates)
    add_custom_command(TARGET main POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${TEMPLATES_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:main>
            ${TEMPLATES_DIR}/${CMAKE_SYSTEM_TARGET}.exe
        COMMENT "Installing main -> pwny/templates/${CMAKE_SYSTEM_TARGET}.exe")
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

# Lightweight tab library for plugins (no heavy deps)
set(TAB_SOURCES
    src/tab_lite.c
    src/tlv.c
    src/queue.c
    src/log.c
)

add_library(tab STATIC ${TAB_SOURCES})
set_property(TARGET tab PROPERTY C_STANDARD 99)
set_property(TARGET tab PROPERTY POSITION_INDEPENDENT_CODE ON)
set_target_properties(tab PROPERTIES OUTPUT_NAME tab)

# Build tab plugins (POSIX: executables with pipe IPC)
if(PLUGINS)
    file(GLOB PLUGIN_DIRS plugins/*)

    foreach(PLUGIN_DIR ${PLUGIN_DIRS})
        if(IS_DIRECTORY ${PLUGIN_DIR})
            get_filename_component(PLUGIN_NAME ${PLUGIN_DIR} NAME)
            file(GLOB PLUGIN_SOURCES ${PLUGIN_DIR}/*.c ${PLUGIN_DIR}/*.S)

            if(PLUGIN_SOURCES)
                add_executable(plugin_${PLUGIN_NAME} ${PLUGIN_SOURCES})
                target_link_directories(plugin_${PLUGIN_NAME} PRIVATE
                    deps/build/${CMAKE_SYSTEM_TARGET}/lib)
                target_link_libraries(plugin_${PLUGIN_NAME} PRIVATE tab ev)

                if(CMAKE_SYSTEM_NAME STREQUAL Linux)
                    if(CMAKE_SYSTEM_PROCESSOR STREQUAL x64)
                        target_link_options(plugin_${PLUGIN_NAME} PRIVATE
                            -static-pie -Wl,-z,max-page-size=4096)
                    else()
                        target_link_options(plugin_${PLUGIN_NAME} PRIVATE -static-pie)
                    endif()
                endif()

                target_compile_options(plugin_${PLUGIN_NAME} PRIVATE
                    -Os -ffunction-sections -fdata-sections)
                target_link_options(plugin_${PLUGIN_NAME} PRIVATE
                    -Wl,--gc-sections -Wl,--strip-all)
                set_target_properties(plugin_${PLUGIN_NAME} PROPERTIES
                    OUTPUT_NAME ${PLUGIN_NAME}
                    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins)

                # Copy built plugin to pwny/tabs/<platform>/<arch>/ for Python loader
                string(TOLOWER ${CMAKE_SYSTEM_NAME} TABS_PLATFORM)
                set(TABS_ARCH ${CMAKE_SYSTEM_PROCESSOR})
                set(TABS_DIR ${CMAKE_SOURCE_DIR}/pwny/tabs/${TABS_PLATFORM}/${TABS_ARCH})
                add_custom_command(TARGET plugin_${PLUGIN_NAME} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E make_directory ${TABS_DIR}
                    COMMAND ${CMAKE_COMMAND} -E copy
                        $<TARGET_FILE:plugin_${PLUGIN_NAME}>
                        ${TABS_DIR}/${PLUGIN_NAME}
                    COMMENT "Installing plugin ${PLUGIN_NAME} -> pwny/tabs/${TABS_PLATFORM}/${TABS_ARCH}/${PLUGIN_NAME}")
            endif()
        endif()
    endforeach()
endif()

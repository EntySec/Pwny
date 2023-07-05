#
# MIT License
#
# Copyright (c) 2020-2023 EntySec
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

cmake_minimum_required(VERSION 3.0.0)
project(libpwny VERSION 1.0.0)

option(DEBUG "Build in debug mode" OFF)
option(IPHONE "Is iPhone iOS" OFF)

set(SDK "" CACHE PATH "Path to SDK")

if (DEBUG)
    add_compile_definitions(DEBUG)
endif()

include_directories(include api deps/injector/include)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_GENERATOR STREQUAL "MinGW Makefiles")
    add_compile_definitions(WINDOWS)
    add_link_options(-s -lws2_32 -limagehlp)

elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    add_compile_options(-x objective-c -fobjc-arc)

    if(SDK)
        add_compile_options(-isysroot ${SDK})
    endif()

    add_compile_definitions(MACOS)

    if(IPHONE)
        add_compile_definitions(IPHONE)
        add_compile_options(-arch arm64 -arch arm64e)

        add_link_options(-framework Foundation -framework Security -framework AudioToolbox)
        add_link_options(-framework CoreFoundation -framework MediaPlayer -framework UIKit)
        add_link_options(-framework AVFoundation -framework CoreLocation)
        add_link_options(-framework SpringBoardServices -framework IOSurface)

    else()
        add_compile_options(-arch x86_64)
        add_link_options(-framework Foundation -framework AVFoundation -framework AudioToolbox -framework AppKit)
    endif()

else()
    add_compile_definitions(LINUX)
endif()

add_link_options(-L. -linjector)

file(GLOB PWNY_SOURCES src/*.c)
add_library(pwny STATIC ${PWNY_SOURCES})

set_property(TARGET pwny PROPERTY C_STANDART 99)
set_property(TARGET pwny PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(pwny PROPERTIES OUTPUT_NAME pwny)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

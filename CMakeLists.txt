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

add_compile_options(-pedantic-errors)

file(GLOB PWNY_SOURCES src/*.c)
add_library(pwny STATIC ${PWNY_SOURCES})

set_property(TARGET pwny PROPERTY C_STANDART 99)
set_property(TARGET pwny PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(pwny PROPERTIES OUTPUT_NAME pwny)

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    file(GLOB MAIN_SOURCES src/main/dll.c)
else()
    file(GLOB MAIN_SOURCES src/main/main.c)
endif()

add_executable(main ${MAIN_SOURCES})

target_compile_options(main PRIVATE -static -no-pie)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL x64)
    target_compile_options(main PRIVATE -Wl,-z,max-page-size=4096)
endif()

string(TOLOWER ${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR} PATH)

target_link_directories(main PRIVATE deps/${PATH})
target_link_libraries(main PRIVATE pwny injector pawn)

include_directories(include api deps/${PATH})

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    target_link_libraries(main PRIVATE ws2_32 imagehlp)

elseif(CMAKE_SYSTEM_NAME STREQUAL OSX)
    add_compile_options(-x objective-c -fobjc-arc)

    if(SDK)
        add_compile_options(-isysroot ${SDK})
    endif()

    if(IPHONE)
        add_compile_definitions(IPHONE)
        add_compile_options(-arch arm64 -arch arm64e)

        add_link_options(
            -framework Foundation
            -framework Security
            -framework AudioToolbox
            -framework CoreFoundation
            -framework MediaPlayer
            -framework UIKit
            -framework AVFoundation
            -framework CoreLocation
            -framework SpringBoardServices
            -framework IOSurface)

    else()
        add_compile_options(-arch x86_64)
        add_link_options(
            -framework Foundation
            -framework AVFoundation
            -framework AudioToolbox
            -framework AppKit)
    endif()
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

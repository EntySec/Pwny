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

cmake_minimum_required(VERSION 3.5.0)
project(libpwny VERSION 1.0.0)

option(DEBUG "Build in debug mode" OFF)
option(MAIN "Build main executable" OFF)

set(SOURCE src/main/test.c CACHE STRING "File to build as executable")

if (DEBUG)
    add_compile_definitions(DEBUG)
endif()

string(TOLOWER ${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR} PATH)

file(GLOB PWNY_SOURCES src/*.c)
add_library(pwny STATIC ${PWNY_SOURCES})

set_property(TARGET pwny PROPERTY C_STANDART 99)
set_property(TARGET pwny PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(pwny PROPERTIES OUTPUT_NAME pwny)
include_directories(include api pipe deps/${PATH})

if(MAIN)
    file(GLOB MAIN_SOURCES ${SOURCE})
    file(GLOB MAIN_LIBS deps/${PATH}/*.a)

    add_executable(main ${MAIN_SOURCES})

    target_link_options(main PRIVATE ${MAIN_LIBS})
    target_link_libraries(main PRIVATE pwny)

    if(CMAKE_SYSTEM_NAME STREQUAL Windows)
        target_link_libraries(main PRIVATE ws2_32 imagehlp)

    elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
        target_compile_options(main PRIVATE -static -no-pie
                                            -Wl,-Ttext-section=0x1000000)
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    add_compile_definitions(IS_WINDOWS)

elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    add_compile_definitions(IS_MACOS)

elseif(CMAKE_SYSTEM_NAME STREQUAL iOS)
    add_compile_definitions(IS_IPHONE)
    add_compile_options(-arch arm64)

elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
    add_compile_definitions(IS_LINUX)

endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

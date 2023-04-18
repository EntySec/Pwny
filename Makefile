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

ifeq ($(platform), windows)
	ar = x86_64-w64-mingw32-gcc-ar
	cc = x86_64-w64-mingw32-gcc
else
	ifdef arch
		ar = $(arch)-linux-musl-ar
		cc = $(arch)-linux-musl-gcc
	else
		ar = ar
		cc = gcc
	endif
endif

objc_flags = -x objective-c -fobjc-arc

source = src
includes = include
apis = api
build = build

target = libpwny.a
template = $(source)/main/template.c
template_library = $(source)/main/template_library.c

objects = $(patsubst $(source)/%.c, $(build)/%.o, $(wildcard $(source)/*.c))

ifeq ($(platform), $(filter $(platform), linux windows))
	deps_ldflags = -Ldeps -linjector
	deps_cflags = -Ideps/injector/include
endif

cflags = -std=c99 -fPIC -I$(includes) -I$(apis) $(deps_cflags) -pedantic-errors -Wall -Wextra #-Werror
cflags += -DHASH_DEBUG=1 -DDEBUG=1 -D$(shell echo $(platform) | tr '[:lower:]' '[:upper:]')

ldflags = -L. -lpwny $(deps_ldflags)

ifeq ($(platform), $(filter $(platform), linux macos apple_ios))
	ldflags += -ldl
else
	ldflags += -s -lws2_32 -limagehlp
endif

ifeq ($(platform), macos)
	cflags += $(objc_flags) -arch x86_64 -isysroot $(sdk)

	ldflags += -framework Foundation -framework AVFoundation
	ldflags += -framework AudioToolbox -framework Appkit
else ifeq ($(platform), apple_ios)
	cflags += $(objc_flags) -arch arm64 -arch arm64e -isysroot $(sdk)

	ldflags += -F $(sdk)/System/Library/Frameworks
	ldflags += -F $(sdk)/System/Library/PrivateFrameworks

	ldflags += -framework Foundation -framework Security -framework AudioToolbox
	ldflags += -framework CoreFoundation -framework MediaPlayer -framework UIKit
	ldflags += -framework AVFoundation -framework CoreLocation
	ldflags += -framework SpringBoardServices -framework IOSurface
else ifeq ($(platform), linux)
	custom_flags = -static
endif

.PHONY: all setup deps cross build template template-library clean

all: deps build template

build: setup $(target)

setup:
	@ mkdir -p $(build)

clean:
	@ echo [Cleaning build]
	@ rm -rf $(build)
	@ echo [Done cleaning build]

deps:
	@ echo [Installing dependencies]
	@ chmod 777 ./scripts/setup.sh; ./scripts/setup.sh $(platform) $(cc) $(ar)
	@ echo [Done installing dependencies]

cross:
	@ echo [Installing compilers]
	@ chmod 777 ./scripts/cross.sh; ./scripts/cross.sh
	@ echo [Done installing compilers]

$(target): $(objects)
	@ echo [Linking target]
	@ $(ar) rcs $@ $(objects)
	@ echo [Done linking target]

$(build)/%.o: $(source)/%.c
	@ echo [Compiling target $<]
	@ $(cc) $(cflags) -c $< -o $@
	@ echo [Done compiling target]

template: $(target)
	@ echo [Compiling template]
	@ $(cc) $(template) $(cflags) $(custom_flags) $(ldflags) -o pwny.$(platform)
	@ echo [Done compiling template]

template-library: $(target)
	@ echo [Compiling template library]
	@ $(cc) $(template_library) $(cflags) -shared $(ldflags) -o pwny.so
	@ echo [Done compiling template library]

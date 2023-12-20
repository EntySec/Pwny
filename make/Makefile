PLATFORM = linux
ARCH = x64

all: setup libpawn injector sigar libev libeio

setup:
	@echo "[Creating workspace]"
	@mkdir -p ../deps/$(PLATFORM)/$(ARCH)
	@echo "[Done creating workspace]"

include Makefile.libpawn
include Makefile.injector
include Makefile.sigar
include Makefile.libev
include Makefile.libeio

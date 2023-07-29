PLATFORM = linux
ARCH = x64

all: setup libpawn injector

setup:
	@echo "[Creating workspace]"
	@mkdir -p ../deps/$(PLATFORM)/$(ARCH)
	@echo "[Done creating workspace]"

include Makefile.libpawn
include Makefile.injector
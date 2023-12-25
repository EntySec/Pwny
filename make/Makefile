all: setup sigar libev libeio

setup:
	@echo "[Creating workspace]"
	@mkdir -p ../deps/build/
	@echo "[Done creating workspace]"

clean:
	@echo "[Cleaning old build]"
	@rm -rf ../deps/build/
	@echo "[Done cleaning old build]"

include Makefile.libpawn
include Makefile.injector
include Makefile.sigar
include Makefile.libev
include Makefile.libeio

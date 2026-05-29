VERSION ?= dev
CC = gcc
CFLAGS = -g -O2 -W -Wall -I. -DPACKAGE_VERSION=\"$(VERSION)\"
LDFLAGS =
LIBS = -lutil

# Portable musl static deploy artifact (~84 KB stripped) — what ships to remote
# hosts. musl bundles forkpty/openpty in libc, so -lutil is omitted (a native
# musl-gcc has no libutil stub, unlike Alpine). Override MUSL_CC=gcc inside an
# Alpine/musl container, where the system gcc already targets musl.
MUSL_CC ?= musl-gcc
# Arch's gcc spec leaks a phantom -latomic_asneeded into musl-gcc static links
# unless -fno-link-libatomic is passed; vanilla gcc (Alpine) rejects that flag.
# Probe the chosen compiler and use it only when accepted. Lazily expanded (=),
# so this only runs for the `musl` target, not the default glibc build.
MUSL_NOATOMIC = $(shell $(MUSL_CC) -fno-link-libatomic -E -x c /dev/null >/dev/null 2>&1 && echo -fno-link-libatomic)
MUSL_CFLAGS = -Os -static -s $(MUSL_NOATOMIC) -I. -DPACKAGE_VERSION=\"$(VERSION)\"

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  STATIC_FLAG =
else
  STATIC_FLAG = -static
endif

OBJ = attach.o master.o atch.o
SRC = attach.c master.c atch.c

IMAGE = atch-builder
BUILDDIR ?= .

archs = amd64 arm64
arch ?= $(shell arch)

atch: $(OBJ)
	$(CC) -o $(BUILDDIR)/$@ $(STATIC_FLAG) $(LDFLAGS) $(OBJ) $(LIBS)

# Build the portable musl static binary directly from source in one pass.
#   make musl                 -> ./atch    (needs musl-gcc; Arch: pacman -S musl)
#   make musl BUILDDIR=build  -> build/atch
#   make musl MUSL_CC=gcc     -> inside an Alpine/musl container
.PHONY: musl
musl:
	$(MUSL_CC) $(MUSL_CFLAGS) -o $(BUILDDIR)/atch $(SRC)

atch.1.md: README.md scripts/readme2man.sh
	bash scripts/readme2man.sh $< > $@

atch.1: atch.1.md
	pandoc --standalone -t man $< -o $@

man: atch.1

clean:
	rm -f atch $(OBJ) *.1.md *.c~

.PHONY: fmt
fmt:
	docker run --rm -v "$$PWD":/src -w /src alpine:latest sh -c "apk add --no-cache indent && indent -linux $(SRCS) && indent -linux $(SRCS)"

.PHONY: fmt-all
fmt-all:
	$(MAKE) fmt SRCS="*.c"


attach.o: ./attach.c ./atch.h config.h
master.o: ./master.c ./atch.h config.h
atch.o: ./atch.c ./atch.h config.h

.PHONY: build-image
build-image:
	docker build -t $(IMAGE):$(arch) --platform linux/$(arch) -f build.dockerfile .

build-docker: build-image
	$(MAKE) clean
	docker run --rm -v "$$PWD":/src -e VERSION=$(VERSION) -w /src \
		--platform linux/$(arch) $(IMAGE):$(arch) ./build.sh

.PHONY: test
test: build-docker
	docker run --rm -v "$$PWD":/src \
		--platform linux/$(arch) $(IMAGE):$(arch) \
		sh /src/tests/test.sh /src/build/atch

# Remote-bootstrap integration test: spins up sshd on localhost inside the
# container and drives `atch -H` end to end. Needs to start a daemon, so it
# runs the container as root (the default) and installs openssh on the fly.
.PHONY: test-ssh
test-ssh: build-docker
	docker run --rm -v "$$PWD":/src \
		--platform linux/$(arch) $(IMAGE):$(arch) \
		sh /src/tests/ssh-test.sh /src/build/atch

# Cross-user sharing test: creates real users and drives the guest listener with
# a tiny SO_PEERCRED connector, so it needs to run the container as root.
.PHONY: test-share
test-share: build-docker
	docker run --rm -v "$$PWD":/src \
		--platform linux/$(arch) $(IMAGE):$(arch) \
		sh /src/tests/cross-share-test.sh /src/build/atch

.PHONY: release
release: man $(archs)

$(archs):
	mkdir -p release
	$(MAKE) build-docker arch=$@ VERSION=$(VERSION)
	export COPYFILE_DISABLE=true; \
	tar -czf ./release/atch-linux-$@.tgz README.md atch.1 -C ./build atch; \

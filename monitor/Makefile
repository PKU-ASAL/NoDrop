MODULE := pinject
TARGET := client

PRIM_C_FILES := main.c
C_FILES := $(PRIM_C_FILES) context.c
S_FILES := misc.S

INCLUDE_PATH := -I. -I../include
CFLAGS := $(INCLUDE_PATH) -std=gnu11 -fPIC -g -Og
LDFLAGS := -nostartfiles -Wl,-Tscript_x86-64.ld -Wl,-znow 

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

DPDK_CFLAGS  := $(shell $(PKGCONF) --cflags libdpdk) -DALLOW_EXPERIMENTAL_API
DPDK_LDFLAGS := $(shell $(PKGCONF) --libs libdpdk)

O_FILES := $(patsubst %.c,%.o,$(C_FILES)) 
O_FILES += $(patsubst %.S,%.o,$(S_FILES))

all: $(TARGET) $(TARGET)-prim

$(TARGET): $(O_FILES)
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	$(CC) $^ -o $@ $(LDFLAGS) $(DPDK_LDFLAGS)

$(TARGET)-prim: $(PRIM_C_FILES)
	$(CC) $^ -o $@ $(DPDK_CFLAGS) -DPRIMARY $(DPDK_LDFLAGS)

%.o: %.S
	$(CC) $< -c $(CFLAGS) $(DPDK_CFLAGS) -o $@ $(LDFLAGS) $(DPDK_LDFLAGS)
%.o: %.c
	$(CC) $< -c $(CFLAGS) $(DPDK_CFLAGS) -o $@ $(LDFLAGS) $(DPDK_LDFLAGS)

.PHONY: clean all
clean:
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	rm -f $(TARGET) $(TARGET)-prim $(O_FILES)

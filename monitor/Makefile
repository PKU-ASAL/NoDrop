
# CFLAGS := $(INCLUDE_PATH) -std=gnu11 -fgnu89-inline -O2 -Wundef -Wwrite-strings\
# 		 -fmerge-all-constants -fno-stack-protector -frounding-math -g -Wstrict-prototypes -Wold-style-definition\
# 		 -fPIC  -fno-stack-protector -mno-mmx  -ftls-model=initial-exec -MD -MP\

INCLUDE_PATH := -I. -I../include
CFLAGS := $(INCLUDE_PATH) -std=gnu11 -fPIC -O2
LDFALGS := -nostartfiles -Wl,-znow -Wl,-Tscript_x86-64.ld #-Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 #-nostdlib -Wl,-z,combreloc -Wl,-z,relro -Wl,--hash-style=both #-Wl,-z,defs

TARGET := hello
MODULE := pinject
C_FILES := hello.c context.c
S_FILES := misc.S
O_FILES := $(patsubst %.c,%.o,$(C_FILES)) 
O_FILES += $(patsubst %.S,%.o,$(S_FILES))

all: $(TARGET) 

$(TARGET): $(O_FILES)
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	$(CC) $(LDFALGS) $^ -o $@ 

%.o: %.S
	$(CC) $< -c $(CFLAGS) -o $@
%.o: %.c
	$(CC) $< -c $(CFLAGS) -o $@

.PHONY: clean all
clean:
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	rm -f $(TARGET) $(O_FILES)

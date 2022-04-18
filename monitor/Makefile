MODULE := nodrop
TARGET := monitor

CC := /usr/bin/gcc-8
LD := /usr/bin/gcc-8
STRIP := /usr/bin/strip

INCLUDE_PATH += -I. -I../include
SPECS := -specs ./musl.specs
CFLAGS_ALL := $(CFLAGS) -std=gnu11 -fPIE -fno-stack-protector $(SPECS) $(INCLUDE_PATH)
LDFLAGS_ALL := $(LDFLAGS) --static-pie -Wl,-Tscript_x86-64.ld $(SPECS)

PRIM_C_FILES := main.c\
				events_table.c\
				flags_table.c\
				dynamic_params_table.c\

C_FILES := $(PRIM_C_FILES) startup.c
O_FILES := $(patsubst %.c,%.o,$(notdir $(C_FILES))) 

all: random $(TARGET)
	@rm _random.h

$(TARGET): $(O_FILES) 
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	$(LD) $^ -o $@ $(LDFLAGS_ALL)
	$(STRIP) -R .symtab $@ -o $@

%.o: %.c
	$(CC) -c $(CFLAGS_ALL) $< -o $@
%.o: ../src/%.c
	$(CC) -c $(CFLAGS_ALL) $< -o $@


.PHONY: clean all random
random:
	@/bin/sh -c ./randgen.sh > _$@.h
clean:
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	rm -f $(TARGET) $(O_FILES)
